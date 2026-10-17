<?php

namespace VoltCMS\UserAccess;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithms;
use Exception;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRecord;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

// Passkey (WebAuthn) registration and sign-in, built on web-auth/webauthn-lib.
//
// Each ceremony takes two requests: the server issues options carrying a
// random challenge, the browser passes them to navigator.credentials.create()
// or .get(), and the server verifies the result against those same options.
// The pending options wait in the PHP session, so a SessionAuth must have
// started it. They are single-use: taken out of the session before the
// response is verified, whatever the outcome, so a captured response cannot be
// replayed.
//
// Sign-in is username-less. The request options list no credentials, the
// authenticator offers the discoverable ones it holds for this relying party,
// and the credential that comes back identifies the user, so the options
// endpoint reveals nothing about which accounts exist. That is why
// registration requires a discoverable (resident) key. Both ceremonies require
// user verification (biometric or PIN) because a passkey replaces the password
// rather than adding a second factor to it.
//
// Like Bearer tokens, failed sign-ins are not run through LoginThrottle: an
// assertion is a signature over a fresh challenge, so there is nothing to
// guess.
//
// webauthn-lib is an optional dependency (composer "suggest"): it brings about
// thirty packages, which hosts that never offer passkeys should not carry. This
// is the only class that needs it to load, so check isAvailable() before
// wiring passkey routes.
class PasskeyAuth
{
    public const SESSION_KEY = 'UA_PASSKEY_CEREMONY';
    // How long, in milliseconds, the browser gives the user to finish a
    // ceremony. WebAuthn recommends 300000-600000 when user verification is
    // required.
    public const DEFAULT_TIMEOUT = 300000;
    private const CEREMONY_REGISTRATION = 'registration';
    private const CEREMONY_LOGIN = 'login';
    private const CHALLENGE_LENGTH = 32;

    private UserProviderInterface $userProvider;
    private PasskeyProviderInterface $passkeyProvider;
    private PublicKeyCredentialRpEntity $relyingParty;
    private int $timeout;
    private SerializerInterface $serializer;
    private CeremonyStepManagerFactory $ceremonyStepManagerFactory;
    private AuditLog $auditLog;

    // $rpId is the domain passkeys are scoped to ("example.com"); $allowedOrigins
    // are the exact origins a ceremony may run from ("https://example.com",
    // "https://admin.example.com:8443"). Neither is derived from the request:
    // the Host header is client-controlled, and trusting it would undo the
    // phishing resistance passkeys exist for.
    public function __construct(UserProviderInterface $userProvider, PasskeyProviderInterface $passkeyProvider, string $rpId, string $rpName, array $allowedOrigins, int $timeout = self::DEFAULT_TIMEOUT)
    {
        // Fail with instructions rather than an "unknown class" fatal further
        // down when the optional package is missing.
        if (!self::isAvailable()) {
            throw new Exception('Passkeys need the web-auth/webauthn-lib package; install it with: composer require web-auth/webauthn-lib:^5.3');
        }
        $rpId = trim(strtolower($rpId));
        $origins = [];
        foreach ($allowedOrigins as $origin) {
            $origin = trim((string) $origin);
            if ($origin !== '') {
                $origins[] = $origin;
            }
        }
        if ($rpId === '' || empty($origins)) {
            throw new Exception('Passkeys need a relying party id and at least one allowed origin');
        }
        $this->userProvider = $userProvider;
        $this->passkeyProvider = $passkeyProvider;
        $this->relyingParty = PublicKeyCredentialRpEntity::create(trim($rpName) !== '' ? trim($rpName) : $rpId, $rpId);
        $this->timeout = max(1, $timeout);
        // Registration asks for "none" attestation, but some clients (browser
        // extensions in particular) send their own statement regardless. Every
        // format that needs no external metadata service is accepted so those
        // clients can register too; the attestation is not used for trust
        // decisions either way.
        $algorithmManager = Manager::create()->add(ES256::create(), RS256::create());
        $attestationStatementSupportManager = AttestationStatementSupportManager::create([
            NoneAttestationStatementSupport::create(),
            PackedAttestationStatementSupport::create($algorithmManager),
            FidoU2FAttestationStatementSupport::create(),
            AndroidKeyAttestationStatementSupport::create(),
            AppleAttestationStatementSupport::create(),
            TPMAttestationStatementSupport::create(),
        ]);
        $this->serializer = (new WebauthnSerializerFactory($attestationStatementSupportManager))->create();
        $this->ceremonyStepManagerFactory = new CeremonyStepManagerFactory();
        $this->ceremonyStepManagerFactory->setAllowedOrigins($origins);
        $this->ceremonyStepManagerFactory->setAlgorithmManager($algorithmManager);
        $this->ceremonyStepManagerFactory->setAttestationStatementSupportManager($attestationStatementSupportManager);
        $this->auditLog = new AuditLog();
    }

    // Whether webauthn-lib is installed. CredentialRecord arrived in 5.3, the
    // oldest version this class supports.
    public static function isAvailable(): bool
    {
        return class_exists(CredentialRecord::class);
    }

    // Records passkey registrations and deletions, in the same format SCIM uses
    // for its administrative actions. Off unless set.
    public function setAuditLog(AuditLog $auditLog): void
    {
        $this->auditLog = $auditLog;
    }

    // Starts registering a passkey for $user and returns the options for
    // navigator.credentials.create(), in WebAuthn's JSON form (binary values as
    // base64url). The user's existing passkeys are excluded, so the browser
    // refuses to register the same authenticator twice.
    public function getRegistrationOptions(User $user): array
    {
        $excludeCredentials = [];
        foreach ($this->getPasskeys($user) as $passkey) {
            $excludeCredentials[] = $passkey->toCredentialRecord()->getPublicKeyCredentialDescriptor();
        }
        $displayName = $user->getDisplayName() !== '' ? $user->getDisplayName() : $user->getUserName();
        $options = PublicKeyCredentialCreationOptions::create(
            $this->relyingParty,
            PublicKeyCredentialUserEntity::create($user->getUserName(), $user->getId(), $displayName),
            random_bytes(self::CHALLENGE_LENGTH),
            [
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
            ],
            AuthenticatorSelectionCriteria::create(
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $excludeCredentials,
            $this->timeout
        );
        return $this->startCeremony(self::CEREMONY_REGISTRATION, $user->getId(), $options);
    }

    // Finishes a registration begun by getRegistrationOptions() for the same
    // user: verifies the authenticator's response and stores the passkey.
    // $response is the PublicKeyCredential as JSON, base64url-encoded the way
    // credential.toJSON() does it in the browser.
    public function register(User $user, string $response, string $name = ''): Passkey
    {
        // Check the label before spending the challenge, so a bad name does not
        // cost the user a second authenticator prompt.
        $passkey = new Passkey();
        $passkey->setName($name);
        $options = $this->takeCeremony(self::CEREMONY_REGISTRATION, $user->getId(), PublicKeyCredentialCreationOptions::class);
        try {
            $credential = $this->serializer->deserialize($response, PublicKeyCredential::class, 'json');
            if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAttestationResponse) {
                throw new Exception('The response is not a passkey registration.');
            }
            $validator = AuthenticatorAttestationResponseValidator::create($this->ceremonyStepManagerFactory->creationCeremony());
            $record = $validator->check($credential->response, $options, (string) $this->relyingParty->id);
        } catch (Throwable $e) {
            error_log('Passkey registration failed: ' . $e->getMessage());
            throw new Exception('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        }
        $passkey->fromCredentialRecord($record);
        $passkey = $this->passkeyProvider->create($passkey);
        $this->writeAudit('passkey.register', $user, $passkey);
        return $passkey;
    }

    // Starts a passkey sign-in and returns the options for
    // navigator.credentials.get().
    public function getLoginOptions(): array
    {
        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes(self::CHALLENGE_LENGTH),
            $this->relyingParty->id,
            [],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $this->timeout
        );
        return $this->startCeremony(self::CEREMONY_LOGIN, '', $options);
    }

    // Finishes a sign-in begun by getLoginOptions() and returns the passkey's
    // user. Throws EXCEPTION_PASSKEY_VERIFICATION_FAILED when the response does
    // not verify, the passkey is unknown, or its user is gone or inactive; the
    // reason goes to the error log, not the caller. Opening the session is left
    // to SessionAuth::loginWithPasskey().
    public function authenticate(string $response): User
    {
        $options = $this->takeCeremony(self::CEREMONY_LOGIN, '', PublicKeyCredentialRequestOptions::class);
        try {
            $credential = $this->serializer->deserialize($response, PublicKeyCredential::class, 'json');
            if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAssertionResponse) {
                throw new Exception('The response is not a passkey assertion.');
            }
            $passkeys = $this->passkeyProvider->find('credentialId', Utils::base64UrlEncode($credential->rawId));
            if (count($passkeys) !== 1) {
                throw new Exception('The passkey is not registered.');
            }
            $passkey = $passkeys[0];
            if (!$this->userProvider->exists('id', $passkey->getUserId())) {
                throw new Exception('The passkey belongs to a user that no longer exists.');
            }
            $user = $this->userProvider->read('id', $passkey->getUserId());
            if (!$user->isActive()) {
                throw new Exception('The passkey belongs to an inactive user.');
            }
            // No user was identified before the ceremony, so the validator
            // requires the response's user handle to match the stored one.
            $validator = AuthenticatorAssertionResponseValidator::create($this->ceremonyStepManagerFactory->requestCeremony());
            $record = $validator->check($passkey->toCredentialRecord(), $credential->response, $options, (string) $this->relyingParty->id, null);
        } catch (Throwable $e) {
            error_log('Passkey sign-in failed: ' . $e->getMessage());
            throw new Exception('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        }
        // Keep what the assertion updated: a signature counter that stops
        // increasing is how a cloned authenticator shows itself.
        $passkey->fromCredentialRecord($record);
        $passkey->setLastUsed(time());
        $this->passkeyProvider->update($passkey);
        return $user;
    }

    // $user's passkeys, oldest first.
    public function getPasskeys(User $user): array
    {
        $passkeys = $this->passkeyProvider->find('userId', $user->getId());
        usort($passkeys, function (Passkey $a, Passkey $b): int {
            return $a->getCreated() <=> $b->getCreated();
        });
        return $passkeys;
    }

    // Removes one of $user's passkeys. Somebody else's passkey is reported as
    // missing rather than forbidden, so passkey ids cannot be probed.
    public function deletePasskey(User $user, string $passkeyId): void
    {
        $passkeyId = trim(strtolower($passkeyId));
        // The id usually comes straight from a client and FileDB turns it into
        // a file name, so anything but a UUID stops here.
        if (!preg_match(Sanitizer::REGEX_UUID, $passkeyId) || !$this->passkeyProvider->exists('id', $passkeyId)) {
            throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
        }
        $passkey = $this->passkeyProvider->read('id', $passkeyId);
        if ($passkey->getUserId() !== $user->getId()) {
            throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
        }
        $this->passkeyProvider->delete($passkey->getId());
        $this->writeAudit('passkey.delete', $user, $passkey);
    }

    // Keeps a ceremony's options in the session and returns them in the JSON
    // form the browser expects. Registration and sign-in have a slot each; a
    // new ceremony of the same kind replaces the old one, so only the latest
    // challenge is honored.
    private function startCeremony(string $type, string $userId, PublicKeyCredentialOptions $options): array
    {
        $this->requireSession();
        $json = $this->serializer->serialize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);
        $_SESSION[self::SESSION_KEY][$type] = [
            'userId' => $userId,
            'options' => $json,
            'expires' => time() + (int) ceil($this->timeout / 1000),
        ];
        return json_decode($json, true);
    }

    // Takes the pending ceremony of $type out of the session and returns its
    // options. It is spent whatever happens next, so each challenge can be
    // answered once. A registration started for one user cannot be finished
    // for another.
    private function takeCeremony(string $type, string $userId, string $optionsClass): PublicKeyCredentialOptions
    {
        $this->requireSession();
        $ceremony = $_SESSION[self::SESSION_KEY][$type] ?? null;
        unset($_SESSION[self::SESSION_KEY][$type]);
        if (!is_array($ceremony) || ($ceremony['userId'] ?? null) !== $userId || (int) ($ceremony['expires'] ?? 0) < time()) {
            throw new Exception('EXCEPTION_PASSKEY_CEREMONY_MISSING');
        }
        return $this->serializer->deserialize($ceremony['options'], $optionsClass, 'json');
    }

    // The challenge has to survive between the options request and the
    // response; without a session there is nowhere to keep it.
    private function requireSession(): void
    {
        if (!isset($_SESSION) || !is_array($_SESSION)) {
            throw new Exception('Passkeys need an active session; call SessionAuth::getInstance() first');
        }
    }

    private function writeAudit(string $action, User $user, Passkey $passkey): void
    {
        if (!$this->auditLog->isEnabled()) {
            return;
        }
        $this->auditLog->record([
            'actor' => $user->getUserName(),
            'actorType' => 'user',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'action' => $action,
            'targetType' => 'Passkey',
            'targetId' => $passkey->getId(),
            'target' => $passkey->getName(),
            'outcome' => 'success',
        ]);
    }
}

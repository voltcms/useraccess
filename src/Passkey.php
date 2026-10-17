<?php

namespace VoltCMS\UserAccess;

use Exception;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

// A WebAuthn credential ("passkey") registered to a user: the public key plus
// the bookkeeping the WebAuthn spec asks a relying party to keep per credential
// (signature counter, backup flags, transports). Binary values are stored as
// unpadded base64url so the FileDB document stays plain JSON. The entity
// converts to and from webauthn-lib's CredentialRecord only at the ceremony
// boundary, which keeps the on-disk shape independent of the library version.
class Passkey
{
    public const DEFAULT_NAME = 'Passkey';
    public const NAME_MAX_LENGTH = 64;
    // WebAuthn caps a credential id at 1023 bytes (credentialIdLength, §6.5.1).
    public const CREDENTIAL_ID_MAX_LENGTH = 1023;
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';
    private string $_id = '';
    private int $_created = 0;
    private int $_modified = 0;
    private string $userId = '';
    private string $name = self::DEFAULT_NAME;
    private string $credentialId = '';
    private string $publicKey = '';
    private int $signCount = 0;
    private array $transports = [];
    private string $attestationType = 'none';
    // Attestation certificates, PEM, leaf first. Empty for "none" attestation,
    // which is what passkeys are registered with.
    private array $trustPath = [];
    private string $aaguid = self::NIL_AAGUID;
    private ?bool $backupEligible = null;
    private ?bool $backupStatus = null;
    private ?bool $uvInitialized = null;
    private int $lastUsed = 0;

    public function getId(): string
    {
        return $this->_id;
    }

    public function getCreated(): int
    {
        return $this->_created;
    }

    // The id of the User this passkey signs in. Doubles as the WebAuthn user
    // handle, so it is what an authenticator hands back on sign-in.
    public function getUserId(): string
    {
        return $this->userId;
    }

    public function setUserId(string $userId): void
    {
        $userId = trim(strtolower($userId));
        if ($userId === '') {
            throw new Exception('EXCEPTION_EMPTY_ID');
        }
        $this->userId = $userId;
    }

    public function getName(): string
    {
        return $this->name;
    }

    // A label the user picks to tell their passkeys apart ("Work laptop"). A
    // blank name falls back to DEFAULT_NAME rather than failing, since naming is
    // optional at registration.
    public function setName(string $name): void
    {
        $name = trim($name);
        if ($name === '') {
            $name = self::DEFAULT_NAME;
        }
        if (!preg_match('/^[^\p{Cc}]{1,' . self::NAME_MAX_LENGTH . '}$/u', $name)) {
            throw new Exception('EXCEPTION_INVALID_PASSKEY_NAME');
        }
        $this->name = $name;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    // Stored re-encoded, so every spelling of the same bytes ends up as the one
    // canonical string sign-in looks the credential up by.
    public function setCredentialId(string $credentialId): void
    {
        $decoded = Utils::base64UrlDecode(trim($credentialId));
        if ($decoded === null || $decoded === '' || strlen($decoded) > self::CREDENTIAL_ID_MAX_LENGTH) {
            throw new Exception('EXCEPTION_INVALID_PASSKEY');
        }
        $this->credentialId = Utils::base64UrlEncode($decoded);
    }

    // The credential public key as a base64url COSE_Key.
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function setPublicKey(string $publicKey): void
    {
        $decoded = Utils::base64UrlDecode(trim($publicKey));
        if ($decoded === null || $decoded === '') {
            throw new Exception('EXCEPTION_INVALID_PASSKEY');
        }
        $this->publicKey = Utils::base64UrlEncode($decoded);
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function setSignCount(int $signCount): void
    {
        if ($signCount < 0) {
            throw new Exception('EXCEPTION_INVALID_PASSKEY');
        }
        $this->signCount = $signCount;
    }

    public function getTransports(): array
    {
        return $this->transports;
    }

    public function setTransports(array $transports): void
    {
        foreach ($transports as $transport) {
            if (!is_string($transport)) {
                throw new Exception('EXCEPTION_INVALID_PASSKEY');
            }
        }
        $this->transports = array_values($transports);
    }

    public function getAttestationType(): string
    {
        return $this->attestationType;
    }

    public function setAttestationType(string $attestationType): void
    {
        $this->attestationType = trim($attestationType);
    }

    public function getTrustPath(): array
    {
        return $this->trustPath;
    }

    public function setTrustPath(array $trustPath): void
    {
        foreach ($trustPath as $certificate) {
            if (!is_string($certificate)) {
                throw new Exception('EXCEPTION_INVALID_PASSKEY');
            }
        }
        $this->trustPath = array_values($trustPath);
    }

    // The authenticator model's AAGUID; all zeroes when the authenticator does
    // not disclose it.
    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    // Only the shape is checked: an AAGUID is 128 arbitrary bits, so the RFC
    // 4122 version and variant rules Uuid::isValid() applies do not hold.
    public function setAaguid(string $aaguid): void
    {
        $aaguid = trim(strtolower($aaguid));
        if (!preg_match(Sanitizer::REGEX_UUID, $aaguid)) {
            throw new Exception('EXCEPTION_INVALID_PASSKEY');
        }
        $this->aaguid = $aaguid;
    }

    // Whether the passkey may be synced to other devices (a cloud keychain)
    // rather than being bound to one authenticator.
    public function getBackupEligible(): ?bool
    {
        return $this->backupEligible;
    }

    public function setBackupEligible(?bool $backupEligible): void
    {
        $this->backupEligible = $backupEligible;
    }

    public function getBackupStatus(): ?bool
    {
        return $this->backupStatus;
    }

    public function setBackupStatus(?bool $backupStatus): void
    {
        $this->backupStatus = $backupStatus;
    }

    public function getUvInitialized(): ?bool
    {
        return $this->uvInitialized;
    }

    public function setUvInitialized(?bool $uvInitialized): void
    {
        $this->uvInitialized = $uvInitialized;
    }

    // Unix time of the last successful sign-in; 0 when never used.
    public function getLastUsed(): int
    {
        return $this->lastUsed;
    }

    public function setLastUsed(int $lastUsed): void
    {
        $this->lastUsed = $lastUsed;
    }

    public function toCredentialRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            (string) Utils::base64UrlDecode($this->credentialId),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $this->transports,
            $this->attestationType,
            empty($this->trustPath) ? EmptyTrustPath::create() : CertificateTrustPath::create($this->trustPath),
            Uuid::fromString($this->aaguid),
            (string) Utils::base64UrlDecode($this->publicKey),
            $this->userId,
            $this->signCount,
            null,
            $this->backupEligible,
            $this->backupStatus,
            $this->uvInitialized
        );
    }

    // Copies a verified credential record onto this entity: every field after
    // registration, and after each sign-in the counter and flags the assertion
    // updated. The record's user handle is the owning user's id.
    public function fromCredentialRecord(CredentialRecord $record): void
    {
        $this->setUserId($record->userHandle);
        $this->setCredentialId(Utils::base64UrlEncode($record->publicKeyCredentialId));
        $this->setPublicKey(Utils::base64UrlEncode($record->credentialPublicKey));
        $this->setSignCount($record->counter);
        $this->setTransports($record->transports);
        $this->setAttestationType($record->attestationType);
        $this->setTrustPath($record->trustPath instanceof CertificateTrustPath ? $record->trustPath->certificates : []);
        $this->setAaguid($record->aaguid->toRfc4122());
        $this->setBackupEligible($record->backupEligible);
        $this->setBackupStatus($record->backupStatus);
        $this->setUvInitialized($record->uvInitialized);
    }

    // The view a "your passkeys" list needs. Leaves out the key material and
    // the counter: a browser has no use for them.
    public function toArray(): array
    {
        return [
            'id' => $this->_id,
            'name' => $this->name,
            'created' => $this->_created === 0 ? null : date(DATE_ATOM, $this->_created),
            'lastUsed' => $this->lastUsed === 0 ? null : date(DATE_ATOM, $this->lastUsed),
            'synced' => $this->backupStatus === true,
            'transports' => $this->transports,
        ];
    }

    public function getAttributes(): array
    {
        $attributes = [];
        $attributes['_id'] = $this->_id;
        $attributes['_created'] = $this->_created;
        $attributes['_modified'] = $this->_modified;
        $attributes['userId'] = $this->userId;
        $attributes['name'] = $this->name;
        $attributes['credentialId'] = $this->credentialId;
        $attributes['publicKey'] = $this->publicKey;
        $attributes['signCount'] = $this->signCount;
        $attributes['transports'] = $this->transports;
        $attributes['attestationType'] = $this->attestationType;
        $attributes['trustPath'] = $this->trustPath;
        $attributes['aaguid'] = $this->aaguid;
        $attributes['backupEligible'] = $this->backupEligible;
        $attributes['backupStatus'] = $this->backupStatus;
        $attributes['uvInitialized'] = $this->uvInitialized;
        $attributes['lastUsed'] = $this->lastUsed;
        return $attributes;
    }

    public function setAttributes(array $attributes): void
    {
        if (array_key_exists('_id', $attributes)) {
            $this->_id = $attributes['_id'];
        }
        // FileDB writes its timestamps as floats (round(microtime(true))).
        if (array_key_exists('_created', $attributes)) {
            $this->_created = (int) $attributes['_created'];
        }
        if (array_key_exists('_modified', $attributes)) {
            $this->_modified = (int) $attributes['_modified'];
        }
        if (array_key_exists('userId', $attributes)) {
            $this->setUserId($attributes['userId']);
        }
        if (array_key_exists('name', $attributes)) {
            $this->setName($attributes['name']);
        }
        if (array_key_exists('credentialId', $attributes)) {
            $this->setCredentialId($attributes['credentialId']);
        }
        if (array_key_exists('publicKey', $attributes)) {
            $this->setPublicKey($attributes['publicKey']);
        }
        if (array_key_exists('signCount', $attributes)) {
            $this->setSignCount($attributes['signCount']);
        }
        if (array_key_exists('transports', $attributes)) {
            $this->setTransports($attributes['transports']);
        }
        if (array_key_exists('attestationType', $attributes)) {
            $this->setAttestationType($attributes['attestationType']);
        }
        if (array_key_exists('trustPath', $attributes)) {
            $this->setTrustPath($attributes['trustPath']);
        }
        if (array_key_exists('aaguid', $attributes)) {
            $this->setAaguid($attributes['aaguid']);
        }
        if (array_key_exists('backupEligible', $attributes)) {
            $this->setBackupEligible($attributes['backupEligible']);
        }
        if (array_key_exists('backupStatus', $attributes)) {
            $this->setBackupStatus($attributes['backupStatus']);
        }
        if (array_key_exists('uvInitialized', $attributes)) {
            $this->setUvInitialized($attributes['uvInitialized']);
        }
        if (array_key_exists('lastUsed', $attributes)) {
            $this->setLastUsed($attributes['lastUsed']);
        }
    }

}

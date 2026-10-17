<?php

use PHPUnit\Framework\TestCase;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\PasskeyAuth;
use VoltCMS\UserAccess\PasskeyProvider;
use VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;
use VoltCMS\UserAccess\Utils;

// Runs real WebAuthn ceremonies against PasskeyAuth. The tests play the
// authenticator themselves: a P-256 key pair per credential, "none"
// attestation, and just enough CBOR to encode it, so every response goes
// through webauthn-lib's actual verification.
class PasskeyAuthTest extends TestCase
{
    private const RP_ID = 'localhost';
    private const ORIGIN = 'http://localhost:8000';
    // Authenticator data flags (WebAuthn §6.1): user present, user verified,
    // attested credential data included.
    private const FLAG_UP = 0x01;
    private const FLAG_UV = 0x04;
    private const FLAG_AT = 0x40;

    private UserProvider $userProvider;
    private GroupProvider $groupProvider;
    private PasskeyProvider $passkeyProvider;
    private PasskeyAuth $passkeyAuth;
    private SessionAuth $sessionAuth;
    private User $user;
    private ?array $sessionBackup;
    private array $serverBackup;

    protected function setUp(): void
    {
        $this->sessionBackup = $_SESSION ?? null;
        $this->serverBackup = $_SERVER;
        $_SESSION = [];
        $this->userProvider = UserProvider::getInstance(['directory' => 'tests/data/users']);
        $this->groupProvider = GroupProvider::getInstance(['directory' => 'tests/data/groups']);
        $this->passkeyProvider = PasskeyProvider::getInstance(['directory' => 'tests/data/passkeys']);
        $this->userProvider->deleteAll();
        $this->passkeyProvider->deleteAll();
        $this->user = $this->createUser('passkeyuser');
        $this->passkeyAuth = new PasskeyAuth($this->userProvider, $this->passkeyProvider, self::RP_ID, 'Test', [self::ORIGIN]);
        // Adding a passkey needs a recent sign-in, so every test starts signed
        // in with the password, through a SessionAuth built on these providers.
        self::resetSessionAuth();
        $this->sessionAuth = SessionAuth::getInstance($this->userProvider, $this->groupProvider);
        $this->sessionAuth->login('passkeyuser', 'password');
    }

    protected function tearDown(): void
    {
        $this->passkeyProvider->deleteAll();
        $this->userProvider->deleteAll();
        // Drop the SessionAuth singleton so these providers do not leak into
        // other test classes.
        self::resetSessionAuth();
        // A session another test starts expects $_SESSION to be an array.
        $_SESSION = $this->sessionBackup ?? [];
        $_SERVER = $this->serverBackup;
    }

    private static function resetSessionAuth(): void
    {
        $instance = new ReflectionProperty(SessionAuth::class, 'instance');
        $instance->setValue(null, null);
    }

    // Moves the session's last sign-in back in time, past a window of $seconds.
    private static function ageAuthentication(int $seconds): void
    {
        $_SESSION[SessionAuth::UA_AUTHENTICATED]['time'] = time() - $seconds - 1;
    }

    private function createUser(string $userName): User
    {
        $user = new User();
        $user->setUserName($userName);
        $user->setDisplayName('Passkey User');
        $user->setPassword('password');
        return $this->userProvider->create($user);
    }

    // Answers registration $options the way navigator.credentials.create()
    // would. Returns the response JSON and the key material a later assertion
    // signs with.
    private function createCredential(array $options, string $origin = self::ORIGIN, int $flags = self::FLAG_UP | self::FLAG_UV | self::FLAG_AT): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $details = openssl_pkey_get_details($key);
        $coseKey = self::cborMap([
            [self::cborInt(1), self::cborInt(2)],
            [self::cborInt(3), self::cborInt(-7)],
            [self::cborInt(-1), self::cborInt(1)],
            [self::cborInt(-2), self::cborBytes(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT))],
            [self::cborInt(-3), self::cborBytes(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT))],
        ]);
        $credentialId = random_bytes(16);
        $authenticatorData = hash('sha256', $options['rp']['id'], true) . chr($flags) . pack('N', 0)
            . str_repeat("\0", 16) . pack('n', strlen($credentialId)) . $credentialId . $coseKey;
        $attestationObject = self::cborMap([
            [self::cborText('fmt'), self::cborText('none')],
            [self::cborText('attStmt'), self::cborMap([])],
            [self::cborText('authData'), self::cborBytes($authenticatorData)],
        ]);
        $clientData = json_encode(['type' => 'webauthn.create', 'challenge' => $options['challenge'], 'origin' => $origin, 'crossOrigin' => false]);
        return [
            'credentialId' => $credentialId,
            'key' => $key,
            'userHandle' => Utils::base64UrlDecode($options['user']['id']),
            'response' => json_encode([
                'id' => Utils::base64UrlEncode($credentialId),
                'rawId' => Utils::base64UrlEncode($credentialId),
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => Utils::base64UrlEncode($clientData),
                    'attestationObject' => Utils::base64UrlEncode($attestationObject),
                    'transports' => ['internal'],
                ],
            ]),
        ];
    }

    // Answers sign-in $options the way navigator.credentials.get() would.
    private function signAssertion(array $options, array $credential, int $signCount = 1, string $origin = self::ORIGIN, int $flags = self::FLAG_UP | self::FLAG_UV): string
    {
        $authenticatorData = hash('sha256', $options['rpId'], true) . chr($flags) . pack('N', $signCount);
        $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => $options['challenge'], 'origin' => $origin, 'crossOrigin' => false]);
        openssl_sign($authenticatorData . hash('sha256', $clientData, true), $signature, $credential['key'], OPENSSL_ALGO_SHA256);
        return json_encode([
            'id' => Utils::base64UrlEncode($credential['credentialId']),
            'rawId' => Utils::base64UrlEncode($credential['credentialId']),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Utils::base64UrlEncode($clientData),
                'authenticatorData' => Utils::base64UrlEncode($authenticatorData),
                'signature' => Utils::base64UrlEncode($signature),
                'userHandle' => Utils::base64UrlEncode($credential['userHandle']),
            ],
        ]);
    }

    // Registers a passkey for the test user and returns its credential, with
    // the stored Passkey under 'passkey'.
    private function registerPasskey(string $name = ''): array
    {
        $credential = $this->createCredential($this->passkeyAuth->getRegistrationOptions($this->user));
        $credential['passkey'] = $this->passkeyAuth->register($this->user, $credential['response'], $name);
        return $credential;
    }

    private static function cborHead(int $majorType, int $length): string
    {
        if ($length < 24) {
            return chr($majorType << 5 | $length);
        }
        if ($length < 256) {
            return chr($majorType << 5 | 24) . chr($length);
        }
        return chr($majorType << 5 | 25) . pack('n', $length);
    }

    private static function cborInt(int $value): string
    {
        return $value >= 0 ? self::cborHead(0, $value) : self::cborHead(1, -1 - $value);
    }

    private static function cborBytes(string $value): string
    {
        return self::cborHead(2, strlen($value)) . $value;
    }

    private static function cborText(string $value): string
    {
        return self::cborHead(3, strlen($value)) . $value;
    }

    // $entries is a list of already-encoded [key, value] pairs.
    private static function cborMap(array $entries): string
    {
        $encoded = self::cborHead(5, count($entries));
        foreach ($entries as [$key, $value]) {
            $encoded .= $key . $value;
        }
        return $encoded;
    }

    public function testConstructorRequiresARelyingPartyIdAndAnOrigin(): void
    {
        $this->expectException(Exception::class);
        new PasskeyAuth($this->userProvider, $this->passkeyProvider, self::RP_ID, 'Test', ['  ']);
    }

    public function testCeremoniesNeedASession(): void
    {
        unset($_SESSION);
        $this->expectExceptionMessage('Passkeys need an active session');
        $this->passkeyAuth->getLoginOptions();
    }

    public function testRegistrationOptionsAskForADiscoverableUserVerifiedPasskey(): void
    {
        $options = $this->passkeyAuth->getRegistrationOptions($this->user);

        $this->assertSame(['id' => self::RP_ID, 'name' => 'Test'], $options['rp']);
        $this->assertSame($this->user->getId(), Utils::base64UrlDecode($options['user']['id']));
        $this->assertSame('passkeyuser', $options['user']['name']);
        $this->assertSame('Passkey User', $options['user']['displayName']);
        $this->assertSame(32, strlen(Utils::base64UrlDecode($options['challenge'])));
        $this->assertSame([-7, -257], array_column($options['pubKeyCredParams'], 'alg'));
        $this->assertSame('required', $options['authenticatorSelection']['residentKey']);
        $this->assertSame('required', $options['authenticatorSelection']['userVerification']);
        $this->assertSame('none', $options['attestation']);
        $this->assertSame(PasskeyAuth::DEFAULT_TIMEOUT, $options['timeout']);
        // Nulls are left out: browsers reject null for enum members.
        $this->assertArrayNotHasKey('authenticatorAttachment', $options['authenticatorSelection']);
        $this->assertSame([], $options['excludeCredentials']);
    }

    public function testRegisterStoresThePasskeyForTheUser(): void
    {
        $credential = $this->registerPasskey('Work laptop');
        $passkey = $credential['passkey'];

        $this->assertSame($this->user->getId(), $passkey->getUserId());
        $this->assertSame('Work laptop', $passkey->getName());
        $this->assertSame(Utils::base64UrlEncode($credential['credentialId']), $passkey->getCredentialId());
        $this->assertSame(['internal'], $passkey->getTransports());
        $this->assertSame('none', $passkey->getAttestationType());
        $this->assertCount(1, $this->passkeyAuth->getPasskeys($this->user));
    }

    public function testRegistrationOptionsExcludeTheUsersPasskeys(): void
    {
        $credential = $this->registerPasskey();
        $options = $this->passkeyAuth->getRegistrationOptions($this->user);

        $this->assertSame([Utils::base64UrlEncode($credential['credentialId'])], array_column($options['excludeCredentials'], 'id'));
    }

    public function testRegisterRejectsAResponseFromAForeignOrigin(): void
    {
        $credential = $this->createCredential($this->passkeyAuth->getRegistrationOptions($this->user), 'https://evil.example');
        try {
            $this->passkeyAuth->register($this->user, $credential['response']);
            $this->fail('A response from a foreign origin was accepted.');
        } catch (Exception $e) {
            $this->assertSame('EXCEPTION_PASSKEY_VERIFICATION_FAILED', $e->getMessage());
        }
        $this->assertSame([], $this->passkeyAuth->getPasskeys($this->user));
    }

    public function testRegisterRequiresUserVerification(): void
    {
        $credential = $this->createCredential($this->passkeyAuth->getRegistrationOptions($this->user), self::ORIGIN, self::FLAG_UP | self::FLAG_AT);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->register($this->user, $credential['response']);
    }

    public function testRegisterRejectsMalformedJson(): void
    {
        $this->passkeyAuth->getRegistrationOptions($this->user);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->register($this->user, '{"id": 1}');
    }

    public function testRegisterWithoutPendingCeremonyFails(): void
    {
        $this->expectExceptionMessage('EXCEPTION_PASSKEY_CEREMONY_MISSING');
        $this->passkeyAuth->register($this->user, '{}');
    }

    public function testRegistrationChallengeCanBeAnsweredOnlyOnce(): void
    {
        $credential = $this->registerPasskey();

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_CEREMONY_MISSING');
        $this->passkeyAuth->register($this->user, $credential['response']);
    }

    public function testRegistrationStartedForOneUserCannotFinishForAnother(): void
    {
        $credential = $this->createCredential($this->passkeyAuth->getRegistrationOptions($this->user));
        $other = $this->createUser('otheruser');

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_CEREMONY_MISSING');
        $this->passkeyAuth->register($other, $credential['response']);
    }

    public function testExpiredRegistrationIsRejected(): void
    {
        $credential = $this->createCredential($this->passkeyAuth->getRegistrationOptions($this->user));
        $_SESSION[PasskeyAuth::SESSION_KEY]['registration']['expires'] = time() - 1;

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_CEREMONY_MISSING');
        $this->passkeyAuth->register($this->user, $credential['response']);
    }

    public function testInvalidNameDoesNotSpendTheChallenge(): void
    {
        $credential = $this->createCredential($this->passkeyAuth->getRegistrationOptions($this->user));
        try {
            $this->passkeyAuth->register($this->user, $credential['response'], "two\nlines");
            $this->fail('An invalid passkey name was accepted.');
        } catch (Exception $e) {
            $this->assertSame('EXCEPTION_INVALID_PASSKEY_NAME', $e->getMessage());
        }

        $passkey = $this->passkeyAuth->register($this->user, $credential['response'], 'Phone');
        $this->assertSame('Phone', $passkey->getName());
    }

    public function testLoginOptionsNameNoCredentials(): void
    {
        $this->registerPasskey();
        $options = $this->passkeyAuth->getLoginOptions();

        // Username-less: the options must not reveal whose passkeys exist.
        $this->assertSame([], $options['allowCredentials']);
        $this->assertSame(self::RP_ID, $options['rpId']);
        $this->assertSame('required', $options['userVerification']);
    }

    public function testAuthenticateReturnsThePasskeysUser(): void
    {
        $credential = $this->registerPasskey();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential);

        $user = $this->passkeyAuth->authenticate($assertion);

        $this->assertSame($this->user->getId(), $user->getId());
        $passkey = $this->passkeyProvider->read('id', $credential['passkey']->getId());
        $this->assertSame(1, $passkey->getSignCount());
        $this->assertGreaterThan(0, $passkey->getLastUsed());
    }

    public function testAuthenticateRejectsABadSignature(): void
    {
        $credential = $this->registerPasskey();
        $impostor = $credential;
        $impostor['key'] = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $impostor);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testAuthenticateRejectsAForeignOrigin(): void
    {
        $credential = $this->registerPasskey();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential, 1, 'https://evil.example');

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testAuthenticateRequiresUserVerification(): void
    {
        $credential = $this->registerPasskey();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential, 1, self::ORIGIN, self::FLAG_UP);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testAuthenticateRejectsAnUnregisteredPasskey(): void
    {
        $registrationOptions = $this->passkeyAuth->getRegistrationOptions($this->user);
        $credential = $this->createCredential($registrationOptions);
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testAuthenticateRejectsAnInactiveUser(): void
    {
        $credential = $this->registerPasskey();
        $this->user->setActive(false);
        $this->userProvider->update($this->user);
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testAuthenticateRejectsAReplayedAssertion(): void
    {
        $credential = $this->registerPasskey();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential);
        $this->passkeyAuth->authenticate($assertion);

        // A fresh challenge does not make an old signature valid.
        $this->passkeyAuth->getLoginOptions();
        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testAuthenticateRejectsACounterThatWentBackwards(): void
    {
        $credential = $this->registerPasskey();
        $this->passkeyAuth->authenticate($this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential, 5));

        // A counter that does not increase is how a cloned authenticator shows.
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential, 3);
        $this->expectExceptionMessage('EXCEPTION_PASSKEY_VERIFICATION_FAILED');
        $this->passkeyAuth->authenticate($assertion);
    }

    public function testDeletePasskeyRemovesTheOwnersPasskey(): void
    {
        $credential = $this->registerPasskey();

        $this->passkeyAuth->deletePasskey($this->user, $credential['passkey']->getId());

        $this->assertSame([], $this->passkeyAuth->getPasskeys($this->user));
    }

    public function testDeletePasskeyHidesOtherUsersPasskeys(): void
    {
        $credential = $this->registerPasskey();
        $other = $this->createUser('otheruser');

        try {
            $this->passkeyAuth->deletePasskey($other, $credential['passkey']->getId());
            $this->fail('A user deleted somebody else\'s passkey.');
        } catch (Exception $e) {
            $this->assertSame('EXCEPTION_ENTRY_NOT_EXIST', $e->getMessage());
        }
        $this->assertCount(1, $this->passkeyAuth->getPasskeys($this->user));
    }

    public function testDeletePasskeyRejectsAnIdThatIsNotAUuid(): void
    {
        $this->expectExceptionMessage('EXCEPTION_ENTRY_NOT_EXIST');
        $this->passkeyAuth->deletePasskey($this->user, '../users/' . $this->user->getId());
    }

    public function testRegistrationAndDeletionAreAudited(): void
    {
        $directory = sys_get_temp_dir() . '/ua_passkey_audit_' . uniqid();
        $this->passkeyAuth->setAuditLog(new AuditLog($directory));
        $_SERVER['REMOTE_ADDR'] = '203.0.113.7';

        $credential = $this->registerPasskey('Phone');
        $this->passkeyAuth->deletePasskey($this->user, $credential['passkey']->getId());

        $lines = file($directory . '/audit.log', FILE_IGNORE_NEW_LINES);
        $this->assertCount(2, $lines);
        $registered = json_decode($lines[0], true);
        $this->assertSame('passkey.register', $registered['action']);
        $this->assertSame('passkeyuser', $registered['actor']);
        $this->assertSame('203.0.113.7', $registered['ip']);
        $this->assertSame('Phone', $registered['target']);
        $this->assertSame('passkeyuser', $registered['owner']);
        $this->assertSame('passkey.delete', json_decode($lines[1], true)['action']);
    }

    public function testDeletionByAnAdministratorIsAuditedWithTheAdministratorAsActor(): void
    {
        $directory = sys_get_temp_dir() . '/ua_passkey_audit_' . uniqid();
        $this->passkeyAuth->setAuditLog(new AuditLog($directory));
        $credential = $this->registerPasskey('Lost phone');
        $admin = $this->createUser('adminuser');

        $this->passkeyAuth->deletePasskey($this->user, $credential['passkey']->getId(), $admin);

        $this->assertSame([], $this->passkeyAuth->getPasskeys($this->user));
        $deleted = json_decode(file($directory . '/audit.log', FILE_IGNORE_NEW_LINES)[1], true);
        $this->assertSame('passkey.delete', $deleted['action']);
        $this->assertSame('adminuser', $deleted['actor']);
        $this->assertSame('passkeyuser', $deleted['owner']);
        $this->assertSame('Lost phone', $deleted['target']);
    }

    public function testRegistrationNeedsARecentSignIn(): void
    {
        self::ageAuthentication(PasskeyAuth::DEFAULT_REAUTHENTICATION_WINDOW);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_REAUTHENTICATION_REQUIRED');
        $this->passkeyAuth->getRegistrationOptions($this->user);
    }

    public function testRegistrationNeedsASignedInUser(): void
    {
        $this->sessionAuth->logout();

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_REAUTHENTICATION_REQUIRED');
        $this->passkeyAuth->getRegistrationOptions($this->user);
    }

    public function testAnotherUsersSignInDoesNotCount(): void
    {
        $other = $this->createUser('otheruser');

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_REAUTHENTICATION_REQUIRED');
        $this->passkeyAuth->getRegistrationOptions($other);
    }

    public function testReauthenticationWindowIsConfigurable(): void
    {
        self::ageAuthentication(60);
        $this->passkeyAuth->setReauthenticationWindow(60);

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_REAUTHENTICATION_REQUIRED');
        $this->passkeyAuth->getRegistrationOptions($this->user);
    }

    public function testConfirmingThePasswordAllowsRegistrationAgain(): void
    {
        self::ageAuthentication(PasskeyAuth::DEFAULT_REAUTHENTICATION_WINDOW);

        $this->assertTrue($this->sessionAuth->confirmPassword('password'));
        $options = $this->passkeyAuth->getRegistrationOptions($this->user);
        $this->assertSame(self::RP_ID, $options['rp']['id']);
    }

    public function testPasskeySignInCountsAsARecentSignIn(): void
    {
        $credential = $this->registerPasskey();
        $this->sessionAuth->logout();
        $this->sessionAuth->loginWithPasskey($this->passkeyAuth, $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential));

        $options = $this->passkeyAuth->getRegistrationOptions($this->user);
        $this->assertCount(1, $options['excludeCredentials']);
    }

    public function testLoginWithPasskeyOpensASession(): void
    {
        $credential = $this->registerPasskey();
        $this->sessionAuth->logout();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential);

        $this->assertTrue($this->sessionAuth->loginWithPasskey($this->passkeyAuth, $assertion, $this->sessionAuth->getCsrfToken()));
        $this->assertTrue($this->sessionAuth->isLoggedIn());
        $this->assertSame('passkeyuser', $_SESSION[SessionAuth::UA_USERNAME]);
    }

    public function testFailedPasskeyLoginLeavesTheSessionLoggedOut(): void
    {
        $credential = $this->registerPasskey();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential, 1, 'https://evil.example');

        $this->assertFalse($this->sessionAuth->loginWithPasskey($this->passkeyAuth, $assertion));
        $this->assertFalse($this->sessionAuth->isLoggedIn());
    }

    public function testPasskeyLoginChecksTheCsrfToken(): void
    {
        $credential = $this->registerPasskey();
        $this->sessionAuth->logout();
        $assertion = $this->signAssertion($this->passkeyAuth->getLoginOptions(), $credential);

        $this->assertFalse($this->sessionAuth->loginWithPasskey($this->passkeyAuth, $assertion, 'not-the-token'));
        $this->assertFalse($this->sessionAuth->isLoggedIn());
    }

}

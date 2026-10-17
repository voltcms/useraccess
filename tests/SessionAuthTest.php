<?php

use PHPUnit\Framework\TestCase;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\LoginThrottle;
use VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;

// Recent-authentication tracking and confirmPassword(), which together gate
// sensitive actions such as adding a passkey.
class SessionAuthTest extends TestCase
{
    private const MAX_LOGIN_ATTEMPTS = 3;

    private UserProvider $userProvider;
    private SessionAuth $sessionAuth;
    private User $user;
    private ?array $sessionBackup;

    protected function setUp(): void
    {
        $this->sessionBackup = $_SESSION ?? null;
        $_SESSION = [];
        $this->userProvider = UserProvider::getInstance(['directory' => 'tests/data/users']);
        $groupProvider = GroupProvider::getInstance(['directory' => 'tests/data/groups']);
        $this->userProvider->deleteAll();
        $user = new User();
        $user->setUserName('confirmuser');
        $user->setPassword('password');
        $this->user = $this->userProvider->create($user);
        // A low attempt limit keeps the lockout test short.
        self::resetSessionAuth();
        $this->sessionAuth = SessionAuth::getInstance($this->userProvider, $groupProvider, self::MAX_LOGIN_ATTEMPTS);
        $this->sessionAuth->login('confirmuser', 'password');
    }

    protected function tearDown(): void
    {
        // The lockout is kept in shared storage, not the session; clear it so
        // the next run does not start locked out.
        $throttle = new LoginThrottle();
        $throttle->reset($throttle->key('confirmuser'));
        $this->userProvider->deleteAll();
        self::resetSessionAuth();
        $_SESSION = $this->sessionBackup ?? [];
    }

    private static function resetSessionAuth(): void
    {
        $instance = new ReflectionProperty(SessionAuth::class, 'instance');
        $instance->setValue(null, null);
    }

    public function testSignInCountsAsARecentAuthentication(): void
    {
        $this->assertTrue(SessionAuth::isRecentlyAuthenticated($this->user, 60));
    }

    public function testRecentAuthenticationExpires(): void
    {
        $_SESSION[SessionAuth::UA_AUTHENTICATED]['time'] = time() - 61;

        $this->assertFalse(SessionAuth::isRecentlyAuthenticated($this->user, 60));
    }

    public function testLogoutForgetsTheAuthentication(): void
    {
        $this->sessionAuth->logout();

        $this->assertFalse(SessionAuth::isRecentlyAuthenticated($this->user, 60));
    }

    public function testConfirmPasswordRenewsTheAuthentication(): void
    {
        $_SESSION[SessionAuth::UA_AUTHENTICATED]['time'] = time() - 600;

        $this->assertTrue($this->sessionAuth->confirmPassword('password', $this->sessionAuth->getCsrfToken()));
        $this->assertTrue(SessionAuth::isRecentlyAuthenticated($this->user, 60));
    }

    public function testWrongPasswordIsRejectedButKeepsTheSession(): void
    {
        $_SESSION[SessionAuth::UA_AUTHENTICATED]['time'] = time() - 600;

        $this->assertFalse($this->sessionAuth->confirmPassword('wrong-password'));
        $this->assertTrue($this->sessionAuth->isLoggedIn());
        $this->assertFalse(SessionAuth::isRecentlyAuthenticated($this->user, 60));
    }

    public function testConfirmPasswordChecksTheCsrfToken(): void
    {
        $this->assertFalse($this->sessionAuth->confirmPassword('password', 'not-the-token'));
    }

    public function testConfirmPasswordNeedsASignedInUser(): void
    {
        $this->sessionAuth->logout();

        $this->assertFalse($this->sessionAuth->confirmPassword('password'));
    }

    public function testConfirmPasswordSharesTheLoginLockout(): void
    {
        for ($i = 0; $i < self::MAX_LOGIN_ATTEMPTS; $i++) {
            $this->sessionAuth->confirmPassword('wrong-password');
        }

        // Locked out: even the right password is refused, so confirmPassword()
        // cannot be used to guess around login()'s limit.
        $this->assertFalse($this->sessionAuth->confirmPassword('password'));
        $this->assertSame(429, http_response_code());
    }

}

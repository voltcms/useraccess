<?php

namespace VoltCMS\UserAccess;

use \Exception;

class SessionAuth
{

    const HTTP_REFERER = 'HTTP_REFERER';
    const HTTP_X_CSRF_TOKEN = 'HTTP_X_CSRF_TOKEN';
    const UA_AUTH = 'UA_AUTH';
    const UA_USERNAME = 'UA_USERNAME';
    const UA_DISPLAYNAME = 'UA_DISPLAYNAME';
    const UA_EMAIL = 'UA_EMAIL';
    const UA_ATTEMPTS = 'UA_ATTEMPTS';
    const UA_REFRESH = 'UA_REFRESH';
    const UA_CSRF = 'X-CSRF-Token';

    const SESSION_REFRESH_TIME = 60;

    // private static ?SessionAuth $instance = null;
    // private ?User $loggedInUser = null;

    private static $instance = null;

    private $now = 0;
    private $userProvider = null;
    private $groupProvider = null;
    private $loggedInUser = null;
    private $maxLoginAttempts = 10;
    private $refreshTime = 60;

    // public static function getInstance(array $userProvider): SessionAuth {
    public static function getInstance($userProvider, $groupProvider, $maxLoginAttempts = 10, $refreshTime = 60): SessionAuth
    {
        if (empty($userProvider)) {
            throw new Exception("User Provider cannot be empty");
        }
        if (empty($groupProvider)) {
            throw new Exception("Group Provider cannot be empty");
        }
        if (self::$instance === null) {
            self::$instance = new static();
            self::$instance->now = time();
            self::$instance->userProvider = $userProvider;
            self::$instance->groupProvider = $groupProvider;
            self::$instance->maxLoginAttempts = $maxLoginAttempts;
            self::$instance->refreshTime = $refreshTime;
            self::$instance->startSession();
        }
        return self::$instance;
    }

    private function __construct()
    {}

    private function __clone()
    {}

    public function __wakeup()
    {
        throw new Exception("Cannot unserialize SessionAuth");
    }

    private function startSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            $session_settings = [
                'httponly' => true,
                'samesite' => 'Strict',
            ];
            session_set_cookie_params($session_settings);
            session_start();
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            if (!array_key_exists(self::UA_AUTH, $_SESSION)) {
                $_SESSION[self::UA_AUTH] = false;
            }
            if (!array_key_exists(self::UA_USERNAME, $_SESSION)) {
                $_SESSION[self::UA_USERNAME] = '';
            }
            if (!array_key_exists(self::UA_DISPLAYNAME, $_SESSION)) {
                $_SESSION[self::UA_DISPLAYNAME] = '';
            }
            if (!array_key_exists(self::UA_EMAIL, $_SESSION)) {
                $_SESSION[self::UA_EMAIL] = '';
            }
            if (!array_key_exists(self::UA_ATTEMPTS, $_SESSION)) {
                $_SESSION[self::UA_ATTEMPTS] = 0;
            }
            if (!array_key_exists(self::UA_CSRF, $_SESSION)) {
                if (function_exists('random_bytes')) {
                    $_SESSION[self::UA_CSRF] = bin2hex(random_bytes(32));
                } else {
                    $_SESSION[self::UA_CSRF] = bin2hex(rand());
                }
            }
            if (array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SERVER) && $_SERVER[self::HTTP_X_CSRF_TOKEN] === 'fetch') {
                $this->setHeader(self::UA_CSRF, $_SESSION[self::UA_CSRF]);
            }
            if (!array_key_exists(self::UA_REFRESH, $_SESSION)) {
                $_SESSION[self::UA_REFRESH] = 0;
            }

            // refresh logged in user if last refresh time is too old
            if ($_SESSION[self::UA_AUTH] === true &&
                $_SESSION[self::UA_REFRESH] < self::$instance->now - self::$instance->refreshTime) {
                $user = self::$instance->get($_SESSION[self::UA_USERNAME]);
                if ($user !== null && $user->isActive()) {
                    self::$instance->setSessionInfo($user, 0);
                } else {
                    self::$instance->setSessionInfo(null, 0);
                }
            }
        }
    }

    private function get(string $userName): ?User
    {
        return $this->findUser(self::$instance->userProvider, $userName);
    }

    private function findUser(UserProviderInterface $userProvider, string $userName): ?User
    {
        if (strpos($userName, '@') !== false) {
            $users = $userProvider->find('email', $userName);
            if (!empty($users) && count($users) == 1) {
                return $users[0];
            }
        } else {
            $users = $userProvider->find('userName', $userName);
            if (!empty($users) && count($users) == 1) {
                return $users[0];
            }
        }
        return null;
    }

    private function setSessionInfo(?User $user, int $loginAttempts)
    {
        if ($user !== null) {
            $_SESSION[self::UA_AUTH] = true;
            $_SESSION[self::UA_USERNAME] = $user->getUserName();
            $_SESSION[self::UA_DISPLAYNAME] = $user->getDisplayName();
            $_SESSION[self::UA_EMAIL] = $user->getEmail();
        } else {
            $_SESSION[self::UA_AUTH] = false;
            $_SESSION[self::UA_USERNAME] = '';
            $_SESSION[self::UA_DISPLAYNAME] = '';
            $_SESSION[self::UA_EMAIL] = '';
        }
        $_SESSION[self::UA_ATTEMPTS] = $loginAttempts;
        $_SESSION[self::UA_REFRESH] = self::$instance->now;
        self::$instance->loggedInUser = $user;
    }

    public function login(string $userName, string $password, ?string $csrf_token = null): bool
    {
        $result = false;
        $userName = trim(strtolower($userName));
        $password = trim($password);
        if (!empty($userName) && !empty($password)) {
            $user = $this->get($userName);
            if ($user !== null && $user->isActive() && $_SESSION[self::UA_ATTEMPTS] < $this->maxLoginAttempts + 1) {
                if ($user->verifyPassword($password)) {
                    if (empty($csrf_token) || hash_equals($_SESSION[self::UA_CSRF], $csrf_token)) {
                        $this->setSessionInfo($user, 0);
                        $result = true;
                    }
                }
            }
        }
        if (!$result) {
            $this->setSessionInfo(null, $_SESSION[self::UA_ATTEMPTS] + 1);
            http_response_code(401);
        }
        return $result;
    }

    public function isLoggedIn(): bool
    {
        return $_SESSION[self::UA_AUTH];
    }

    public function enforceLoggedIn(): void
    {
        if (!$this->isLoggedIn()) {
            http_response_code(401);
            $this->echoJsonLoginInfo();
            exit();
        }
    }

    public function getLoginInfo(): array
    {
        return [
            self::UA_AUTH => $_SESSION[self::UA_AUTH],
            self::UA_USERNAME => $_SESSION[self::UA_USERNAME],
            self::UA_ATTEMPTS => $_SESSION[self::UA_ATTEMPTS],
            self::UA_REFRESH => $_SESSION[self::UA_REFRESH],
        ];
    }

    public function echoJsonLoginInfo(): string
    {
        $this->setHeader('Content-Type', 'application/json');
        echo json_encode($this->getLoginInfo());
        exit();
    }

    public function setCsrfTokenHeader(): void
    {
        if (!array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SESSION)) {
            $_SESSION[self::HTTP_X_CSRF_TOKEN] = bin2hex(random_bytes(32));
        }
        if (array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SERVER) && $_SERVER[self::HTTP_X_CSRF_TOKEN] === 'fetch') {
            $this->setHeader(self::HTTP_X_CSRF_TOKEN, $_SESSION[self::HTTP_X_CSRF_TOKEN]);
        }
    }

    public function logout()
    {
        if ($this->isLoggedIn()) {
            $this->setSessionInfo(null, 0);
        }
    }

    private function setHeader(string $key, string $value)
    {
        header($key . ': ' . $value);
    }

    public function getLoggedInUser(): ?User
    {
        if ($this->isLoggedIn()) {
            if ($this->loggedInUser !== null) {
                return $this->loggedInUser;
            } else {
                return $this->get($_SESSION[self::UA_USERNAME]);
            }
        } else {
            return null;
        }
    }

    public function isMemberOfGroup($required_group)
    {
        $required_groups = Sanitizer::sanitizeString($required_group);
        $loggedInUser = $this->getLoggedInUser();
        if (!empty($required_groups[0]) && $loggedInUser && $loggedInUser->isMemberOf($required_group)) {
            return true;
        } else {
            return false;
        }
    }

    public function enforceMemberOfGroup($required_group)
    {
        $this->enforceLoggedIn();
        if (!$this->isMemberOfGroup($required_group)) {
            http_response_code(401);
            $this->echoJsonLoginInfo();
            exit();
        }
    }

}

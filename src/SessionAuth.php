<?php

namespace PragmaPHP\UserAccess;

use Exception;
use \PragmaPHP\UserAccess\User;
use \PragmaPHP\UserAccess\Sanitizer;

class SessionAuth {

    const HTTP_REFERER = 'HTTP_REFERER';
    const HTTP_X_CSRF_TOKEN = 'HTTP_X_CSRF_TOKEN';
    const SESSION_LOGIN_AUTHENTICATED = 'SESSION_LOGIN_AUTHENTICATED';
    const SESSION_LOGIN_USERNAME = 'SESSION_LOGIN_USERNAME';
    const SESSION_LOGIN_GROUPS = 'SESSION_LOGIN_GROUPS';
    const SESSION_LOGIN_ATTEMPTS = 'SESSION_LOGIN_ATTEMPTS';
    const SESSION_LOGIN_CSRF_TOKEN = 'X-CSRF-Token';
    const MAX_LOGIN_ATTEMPTS = 10;

    // private static ?SessionAuth $instance = null;
    // private ?array $userProviders = null;
    // private ?User $loggedInUser = null;

    private static $instance = null;
    private $userProviders = null;
    private $loggedInUser = null;

    // public static function getInstance(array $userProviders): SessionAuth {
    public static function getInstance($userProviders): SessionAuth {
        if (empty($userProviders)) {
            throw new Exception("User Providers cannot be empty");
        }
        if (self::$instance === null) {
            self::$instance = new static();
        }
        self::$instance->userProviders = $userProviders;
        self::$instance->startSession();
        return self::$instance;
    }

    private function __construct() {}

    private function __clone(){}

    public function __wakeup() {
        throw new Exception("Cannot unserialize SessionAuth");
    }

    private function startSession(): void {
        if (session_status() === PHP_SESSION_NONE) {
            $session_settings = [
                'httponly' => true,
                'samesite' => 'Strict'
            ];
            session_set_cookie_params($session_settings);
            session_start();
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            if (!array_key_exists(self::SESSION_LOGIN_AUTHENTICATED, $_SESSION)) {
                $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = false;
            }
            if (!array_key_exists(self::SESSION_LOGIN_USERNAME, $_SESSION)) {
                $_SESSION[self::SESSION_LOGIN_USERNAME] = '';
            }
            if (!array_key_exists(self::SESSION_LOGIN_GROUPS, $_SESSION)) {
                $_SESSION[self::SESSION_LOGIN_GROUPS] = [];
            }
            if (!array_key_exists(self::SESSION_LOGIN_ATTEMPTS, $_SESSION)) {
                $_SESSION[self::SESSION_LOGIN_ATTEMPTS] = 0;
            }
            if (!array_key_exists(self::SESSION_LOGIN_CSRF_TOKEN, $_SESSION)) {
                if (function_exists('random_bytes')) {
                    $_SESSION[self::SESSION_LOGIN_CSRF_TOKEN] = bin2hex(random_bytes(32));
                } else {
                    $_SESSION[self::SESSION_LOGIN_CSRF_TOKEN] = bin2hex(rand());
                }
            }
            if (array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SERVER) && $_SERVER[self::HTTP_X_CSRF_TOKEN] === 'fetch') {
                $this->setHeader(self::SESSION_LOGIN_CSRF_TOKEN, $_SESSION[self::SESSION_LOGIN_CSRF_TOKEN]);
            }
        }
    }

    private function setSessionInfo(bool $loggedIn, string $userName, array $groups, int $loginAttempts, ?User $user) {
        $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = $loggedIn;
        $_SESSION[self::SESSION_LOGIN_USERNAME] = $userName;
        $_SESSION[self::SESSION_LOGIN_GROUPS] = $groups;
        $_SESSION[self::SESSION_LOGIN_ATTEMPTS] = $loginAttempts;
        $this->loggedInUser = $user;
    }

    public function login(string $userName, string $password): bool {
        $result = false;
        $userName = trim(strtolower($userName));
        $password = trim($password);
        if (!empty($userName) && !empty($password)) {
            foreach ($this->userProviders as $userProvider) {
                if ($userProvider->isUserNameExisting($userName)) {
                    $user = $userProvider->getUser($userName);
                    if ($user->isActive() && $_SESSION[self::SESSION_LOGIN_ATTEMPTS] < self::MAX_LOGIN_ATTEMPTS + 1) {
                        if ($user->verifyPassword($password)){
                            $this->setSessionInfo(true, $user->getUserName(), $user->getGroups(), 0, $user);
                            $result = true;
                            break;
                        }
                    }
                }
            }
        }
        if (!$result) {
            $this->setSessionInfo(false, '', [], $_SESSION[self::SESSION_LOGIN_ATTEMPTS] + 1, null);
        }
        return $result;
    }

    public function isLoggedIn(): bool {
        $result = (!empty($_SESSION) && array_key_exists(self::SESSION_LOGIN_AUTHENTICATED, $_SESSION) && $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] === true);
        if ($result) {
            if ($this->loggedInUser === null) {
                $result = false;
                foreach ($this->userProviders as $userProvider) {
                    if ($userProvider->isUserNameExisting($_SESSION[self::SESSION_LOGIN_USERNAME])) {
                        $user = $userProvider->getUser($_SESSION[self::SESSION_LOGIN_USERNAME]);
                        if ($user->isActive()) {
                            $this->setSessionInfo(true, $user->getUserName(), $user->getGroups(), 0, $user);
                            $result = true;
                            break;
                        } else {
                            $this->setSessionInfo(false, '', [] , 0, null);
                            break;
                        }
                    }
                }
            }
        }
        return $result;
    }

    public function enforceLoggedIn(): void {
        if (!$this->isLoggedIn()) {
            http_response_code(401);
            $this->echoJsonLoginInfo();
        }
    }

    public function getLoginInfo(): array {
        return [
            self::SESSION_LOGIN_AUTHENTICATED => $_SESSION[self::SESSION_LOGIN_AUTHENTICATED], 
            self::SESSION_LOGIN_USERNAME => $_SESSION[self::SESSION_LOGIN_USERNAME],
            self::SESSION_LOGIN_GROUPS => $_SESSION[self::SESSION_LOGIN_GROUPS]
        ];
    }

    public function echoJsonLoginInfo(): string {
        $this->setHeader('Content-Type', 'application/json');
        echo json_encode($this->getLoginInfo());
        exit();
    }

    public function setCsrfTokenHeader(): void {
        if (!array_key_exists(HTTP_X_CSRF_TOKEN, $_SESSION)) {
            $_SESSION[HTTP_X_CSRF_TOKEN] = bin2hex(random_bytes(32));;
        }
        if (array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SERVER) && $_SERVER[self::HTTP_X_CSRF_TOKEN] === 'fetch') {
            $this->setHeader(self::HTTP_X_CSRF_TOKEN, $_SESSION[self::HTTP_X_CSRF_TOKEN]);
        }
    }

    public function logout() {
        if ($this->isLoggedIn()) {
            $this->setSessionInfo(false, '', [] , 0, null);
        }
    }

    private function setHeader(string $key, string $value) {
        header($key . ': ' . $value);
    }

    public function getLoggedInUser(): User {
        return $this->loggedInUser;
    }

    public function isMemberOfGroup($required_groups) {
        $required_groups = Sanitizer::sanitizeStringToArray($required_groups);
        if (!empty($required_groups[0]) && empty(array_intersect($required_groups, $_SESSION[self::SESSION_LOGIN_GROUPS]))) {
            return false;
        } else {
            return true;
        }
    }

    public function enforceMemberOfGroup($required_groups) {
        $this->enforceLoggedIn();
        if (!$this->isMemberOfGroup($required_groups)) {
            http_response_code(401);
            $this->echoJsonLoginInfo();
        }
    }

}
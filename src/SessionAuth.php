<?php

namespace PragmaPHP\UserAccess;

use \PragmaPHP\UserAccess\User;

class SessionAuth {

    const SESSION_LOGIN_AUTHENTICATED = 'LOGIN_AUTHENTICATED';
    const SESSION_LOGIN_USERNAME = 'LOGIN_USERNAME';
    const SESSION_LOGIN_GROUPS = 'SESSION_LOGIN_GROUPS';
    const SESSION_LOGIN_ATTEMPTS = 'SESSION_LOGIN_ATTEMPTS';
    const SESSION_LOGIN_CSRF_TOKEN = 'X-CSRF-Token';
    const HTTP_X_CSRF_TOKEN = 'HTTP_X_CSRF_TOKEN';

    public static function startSession(): void {
        if (session_status() === PHP_SESSION_NONE) {
            $session_settings = [
                'httponly' => true,
                'samesite' => 'Strict'
            ];
            session_set_cookie_params($session_settings);
            $session = session_start();
            if ($session) {
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
                    self::setHeader(self::SESSION_LOGIN_CSRF_TOKEN, $_SESSION[self::SESSION_LOGIN_CSRF_TOKEN]);
                }
            }
        }
    }

    public static function login(array $userProviders, string $userName, string $password): bool {
        self::startSession();
        $result = false;
        $userName = trim(strtolower($userName));
        $password = trim($password);
        if (!empty($userProviders) && !empty($userName) && !empty($password)) {
            foreach ($userProviders as $userProvider) {
                if ($userProvider->isUserNameExisting($userName)) {
                    $user = $userProvider->getUser($userName);
                    if ($user->isActive() && $_SESSION[self::SESSION_LOGIN_ATTEMPTS] < 11) {
                        if ($user->verifyPassword($password)){
                            $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = true;
                            $_SESSION[self::SESSION_LOGIN_USERNAME] = $user->getUserName();
                            $_SESSION[self::SESSION_LOGIN_GROUPS] = $user->getGroups();
                            $_SESSION[self::SESSION_LOGIN_ATTEMPTS] = 0;
                            $result = true;
                        }
                    }
                }
            }
        }
        if (!$result) {
            $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = false;
            $_SESSION[self::SESSION_LOGIN_USERNAME] = '';
            $_SESSION[self::SESSION_LOGIN_GROUPS] = [];
            $_SESSION[self::SESSION_LOGIN_ATTEMPTS] = $_SESSION[self::SESSION_LOGIN_ATTEMPTS] + 1;
        }
        return $result;
    }

    public static function isLoggedIn(): bool {
        self::startSession();
        return (!empty($_SESSION) && array_key_exists(self::SESSION_LOGIN_AUTHENTICATED, $_SESSION) && $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] === true);
    }

    public static function enforceLogin(): void {
        if (!self::isLoggedIn()) {
            http_response_code(401);
            self::echoJsonLoginInfo();
        }
    }

    public static function getLoginInfo(): array {
        self::startSession();
        return [
            self::SESSION_LOGIN_AUTHENTICATED => $_SESSION[self::SESSION_LOGIN_AUTHENTICATED], 
            self::SESSION_LOGIN_USERNAME => $_SESSION[self::SESSION_LOGIN_USERNAME],
            self::SESSION_LOGIN_GROUPS => $_SESSION[self::SESSION_LOGIN_GROUPS]
        ];
    }

    public static function echoJsonLoginInfo(): string {
        self::setHeader('Content-Type', 'application/json');
        echo json_encode(self::getLoginInfo());
        exit();
    }

    public static function setCsrfTokenHeader(): void {
        self::startSession();
        if (!array_key_exists(HTTP_X_CSRF_TOKEN, $_SESSION)) {
            $_SESSION[HTTP_X_CSRF_TOKEN] = bin2hex(random_bytes(32));;
        }
        if (array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SERVER) && $_SERVER[self::HTTP_X_CSRF_TOKEN] === 'fetch') {
            self::setHeader(self::HTTP_X_CSRF_TOKEN, $_SESSION[self::HTTP_X_CSRF_TOKEN]);
        }
    }

    public static function logout() {
        self::startSession();
        $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = false;
        $_SESSION[self::SESSION_LOGIN_USERNAME] = '';
        $_SESSION[self::SESSION_LOGIN_GROUPS] = [];
        $_SESSION[self::SESSION_LOGIN_ATTEMPTS] = 0;
    }

    private static function setHeader(string $key, string $value) {
        header($key . ': ' . $value);
    }

}
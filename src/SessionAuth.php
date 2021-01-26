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
                    setHeader(self::SESSION_LOGIN_CSRF_TOKEN, $_SESSION[self::SESSION_LOGIN_CSRF_TOKEN]);
                }
            }
        }
    }

    public static function login(UserProviderInterface $userProviders, string $userName, string $password): String {
        $userName = trim(strtolower($userName));
        $password = trim($password);
        foreach ($userProviders as $userProvider) {
            if (empty($userName) || empty($password) || !$userProvider->isUserNameExisting($userName)) {
                // throw new \Exception(UserAccess::EXCEPTION_AUTHENTICATION_FAILED);
                return echoJsonLogin();
            }
            $users = $userProvider->findUsers('uniqueName', $uniqueName);
            if (empty($users) || \count($users) > 1) {
                // throw new \Exception(UserAccess::EXCEPTION_AUTHENTICATION_FAILED);
                return echoJsonLogin();
            } else {
                $user = current($users);
            }
            if (!$user->isActive() || $user->getLoginAttempts() > 10) {
                // throw new \Exception(UserAccess::EXCEPTION_AUTHENTICATION_FAILED);
                return echoJsonLogin();
            }
            if ($user->verifyPassword($secret)){
                $_SESSION[self::SESSION_LOGIN_USERID] = $user->getId();
                $_SESSION[self::SESSION_LOGIN_USERNAME] = $user->getUserName();
                $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = true;
                // $_SESSION[SESSION_LOGIN_ATTEMPTS] = 0;
                return echoJsonLogin();
            } else {
                // throw new \Exception(UserAccess::EXCEPTION_AUTHENTICATION_FAILED);
                return echoJsonLogin();
            }
        }
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

    public static function echoJsonLoginInfo(): string {
        self::setHeader('Content-Type', 'application/json');
        echo json_encode(self::getLoginInfo());
        exit();
    }

    private static function getLoginInfo(): array {
        return [
            self::SESSION_LOGIN_AUTHENTICATED => $_SESSION[self::SESSION_LOGIN_AUTHENTICATED], 
            self::SESSION_LOGIN_USERNAME => $_SESSION[self::SESSION_LOGIN_USERNAME]
        ];
    }

    public static function setCsrfTokenHeader(): void {
        if (!array_key_exists(HTTP_X_CSRF_TOKEN, $_SESSION)) {
            $_SESSION[HTTP_X_CSRF_TOKEN] = bin2hex(random_bytes(32));;
        }
        if (array_key_exists(self::HTTP_X_CSRF_TOKEN, $_SERVER) && $_SERVER[self::HTTP_X_CSRF_TOKEN] === 'fetch') {
            self::setHeader(self::HTTP_X_CSRF_TOKEN, $_SESSION[self::HTTP_X_CSRF_TOKEN]);
        }
    }

    public static function logout(): array {
        $_SESSION[self::SESSION_LOGIN_AUTHENTICATED] = false;
        $_SESSION[self::SESSION_LOGIN_USERNAME] = '';
        $_SESSION[self::SESSION_LOGIN_GROUPS] = [];
        $_SESSION[self::SESSION_LOGIN_ATTEMPTS] = 0;
        self::echoJsonLoginInfo();
    }

    private static function setHeader(string $key, string $value) {
        header($key . ': ' . $value);
    }

}
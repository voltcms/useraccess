<?php

namespace VoltCMS\UserAccess;

use \Exception;

class HeaderAuth
{

    // A well-formed hash used to equalize verification time when the requested
    // user does not exist, so response timing does not reveal whether a
    // username is valid (username enumeration guard).
    private const DUMMY_PASSWORD_HASH = '$2y$12$KicAYtxg.xPBfMWVd9T/Je38Cmw1QcI70kW91CMD9L0zkpaR3YRpy';

    public static function checkBasicAuthentication($userProvider, ?LoginThrottle $throttle = null): ?User
    {
        $authorizationHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if ($authorizationHeader == '') {
            $authorizationHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        }
        if (!str_starts_with($authorizationHeader, 'Basic ')) {
            return null;
        }
        $base64Credentials = substr($authorizationHeader, 6);
        $decoded = base64_decode($base64Credentials, true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            return null;
        }
        // Split on the first colon only so passwords may contain ':'.
        list($userName, $password) = explode(':', $decoded, 2);
        // Shared brute-force lockout: HTTP Basic has no session to carry a
        // counter, so without this an attacker could retry credentials without
        // limit. Keyed by username + client IP.
        $throttle = $throttle ?? new LoginThrottle();
        $throttleKey = $throttle->key($userName);
        if ($throttle->isLocked($throttleKey)) {
            // Still burn a dummy verify so a locked account is not
            // distinguishable by timing from a rejected password.
            password_verify($password, self::DUMMY_PASSWORD_HASH);
            return null;
        }
        $user = null;
        if ($userProvider->exists('userName', $userName)) {
            $user = $userProvider->read('userName', $userName);
        }
        if ($user !== null) {
            if ($user->verifyPassword($password)) {
                $throttle->reset($throttleKey);
                return $user;
            }
        } else {
            // Perform a dummy verification to keep timing independent of
            // whether the username exists.
            password_verify($password, self::DUMMY_PASSWORD_HASH);
        }
        $throttle->registerFailure($throttleKey);
        return null;
    }

}

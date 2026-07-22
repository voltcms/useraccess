<?php

namespace VoltCMS\UserAccess;

use \Exception;

class HeaderAuth
{

    // A well-formed hash used to equalize verification time when the requested
    // user does not exist, so response timing does not reveal whether a
    // username is valid (username enumeration guard).
    private const DUMMY_PASSWORD_HASH = '$2y$12$KicAYtxg.xPBfMWVd9T/Je38Cmw1QcI70kW91CMD9L0zkpaR3YRpy';

    public static function checkBasicAuthentication($userProvider): ?User
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
        $user = null;
        if ($userProvider->exists('userName', $userName)) {
            $user = $userProvider->read('userName', $userName);
        }
        if ($user !== null) {
            if ($user->verifyPassword($password)) {
                return $user;
            }
        } else {
            // Perform a dummy verification to keep timing independent of
            // whether the username exists.
            password_verify($password, self::DUMMY_PASSWORD_HASH);
        }
        return null;
    }

}

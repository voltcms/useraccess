<?php

namespace VoltCMS\UserAccess;

use \Exception;

class HeaderAuth
{

    public static function checkBasicAuthentication($userProvider): ?User
    {
        $authorizationHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if ($authorizationHeader == '') {
            $authorizationHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        }
        if (str_starts_with($authorizationHeader, 'Basic ')) {
            $base64Credentials = substr($authorizationHeader, 6);
            list($userName, $password) = explode(':', base64_decode($base64Credentials));
            if ($userProvider->exists('userName', $userName)) {
                $user = $userProvider->read('userName', $userName);
                $authenticated = $user->verifyPassword($password);
                if ($authenticated) {
                    return $user;
                }
            }
        }
        return null;
    }

}

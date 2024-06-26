<?php

namespace VoltCMS\UserAccess;

class Utils
{

    const ACCESS_STATUS_EVERYONE = 'everyone';
    const ACCESS_STATUS_LOGGED_IN = 'logged_in';
    const ACCESS_STATUS_LOGGED_IN_MEMBER_OF_GROUP = 'logged_in_member_of_group';
    const ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP = 'logged_in_member_of_group';

    public static function isContentVisible($sessionAuth, $user_status, $logged_in_member_of_group, $logged_in_not_member_of_group)
    {
        if ($user_status === Utils::ACCESS_STATUS_EVERYONE) {
            return true;
        }
        $loggedIn = (substr($user_status, 0, 9) === Utils::ACCESS_STATUS_LOGGED_IN);
        $memberOfGroup = ($user_status === Utils::ACCESS_STATUS_LOGGED_IN_MEMBER_OF_GROUP);
        $notMemberOfGroup = ($user_status === Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP);
        // user must be logged in
        if ($loggedIn && $sessionAuth->isLoggedIn()) {
            if (!$memberOfGroup && !$notMemberOfGroup) {
                return true;
            }
            if ($memberOfGroup && $sessionAuth->isMemberOfGroup($logged_in_member_of_group)) {
                return true;
            }
            if ($notMemberOfGroup && !$sessionAuth->isMemberOfGroup($logged_in_not_member_of_group)) {
                return true;
            }
        }
        if (!$loggedIn && !$sessionAuth->isLoggedIn()) {
            return true;
        }
        return false;
    }

    public static function protectPage($sessionAuth, $user_status, $logged_in_member_of_group, $login_redirect, $forbidden_redirect, $login_page, $forbidden_page)
    {
        if ($user_status === 'everyone') {
            return;
        }
        $memberOfGroup = ($user_status === Utils::ACCESS_STATUS_LOGGED_IN_MEMBER_OF_GROUP);
        $login_redirect = self::getBoolean($login_redirect);
        $forbidden_redirect = self::getBoolean($forbidden_redirect);
        $forbidden = false;
        if (!$sessionAuth->isLoggedIn()) {
            if ($login_redirect) {
                header('Location: ' . $login_page . '?ref=' . $_SERVER['REQUEST_URI']);
                exit();
            } else {
                $forbidden = true;
            }
        } else {
            if ($memberOfGroup && !$sessionAuth->isMemberOfGroup($logged_in_member_of_group)) {
                $forbidden = true;
            }
        }
        if ($forbidden) {
            if ($forbidden_redirect) {
                header('Location: ' . $forbidden_page . '?ref=' . $_SERVER['REQUEST_URI']);
                exit();
            } else {
                ob_end_clean();
                http_response_code(401);
                echo "<h1>Forbidden</h1>";
                exit;
            }
        }
    }

    public static function getRootFolder($relativeDocRoot)
    {
        if ($relativeDocRoot == "") {
            $relativeDocRoot = ".";
        } elseif ($relativeDocRoot[strlen($relativeDocRoot) - 1] == "/") {
            $relativeDocRoot = substr($relativeDocRoot, 0, -1);
        }
        return $relativeDocRoot;
    }

    public static function getDirectory($subfolder, $relativeDocRoot)
    {
        $directory = '';
        if (str_starts_with($subfolder, 'http://') || str_starts_with($subfolder, 'https://')) {
            $subfolder = substr($subfolder, strpos($subfolder, '/', 8));
        }
        if ($subfolder[0] == "/") {
            $subfolder = substr($subfolder, 1);
        }
        if ($subfolder[strlen($subfolder) - 1] !== "/") {
            $subfolder = $subfolder . "/";
        }
        if ($subfolder == "/") {
            $subfolder = "";
        }
        $directory = $relativeDocRoot . $subfolder;
        return $directory;
    }

    public static function getDefault(&$value, $default = null)
    {
        return !empty($value) ? $value : $default;
    }

    public static function getBoolean($booleanString)
    {
        if ($booleanString == "True") {
            return true;
        } else {
            return false;
        }
    }

    public static function setHeader(string $key, string $value)
    {
        header($key . ': ' . $value);
    }

}

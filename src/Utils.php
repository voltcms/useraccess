<?php

namespace VoltCMS\UserAccess;

class Utils
{

    const ACCESS_STATUS_EVERYONE = 'everyone';
    const ACCESS_STATUS_LOGGED_IN = 'logged_in';
    const ACCESS_STATUS_LOGGED_IN_MEMBER_OF_GROUP = 'logged_in_member_of_group';
    const ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP = 'logged_in_not_member_of_group';

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

    // Determines whether the current request is being served over HTTPS.
    // Honors the standard reverse-proxy / load-balancer forwarding headers
    // (`X-Forwarded-Proto`, `X-Forwarded-SSL`) in addition to the direct
    // `HTTPS` server variable, so the secure cookie flag and generated
    // location URLs stay correct behind a TLS-terminating proxy.
    //
    // NOTE: the forwarding headers are only trustworthy when the app sits
    // behind a proxy you control that sets/strips them. Erring towards
    // "https" here is the safe direction: it can only add the `Secure`
    // cookie flag and produce https:// URLs, never weaken them.
    public static function isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') {
            return true;
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
            return true;
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_SSL']) && strtolower($_SERVER['HTTP_X_FORWARDED_SSL']) === 'on') {
            return true;
        }
        if (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
            return true;
        }
        return false;
    }

    // Best-effort defense-in-depth for flat-file data directories: drops a
    // deny-all `.htaccess` and an empty `index.html` into $directory so that,
    // if the directory ever ends up inside an Apache document root, the raw
    // JSON documents (which contain password hashes and PII) cannot be
    // downloaded and the directory cannot be listed.
    //
    // This is a safety net, NOT a substitute for storing the data directory
    // OUTSIDE the web root (the real fix) and does nothing on nginx — see the
    // deployment notes in CLAUDE.md for the nginx equivalent. Failures are
    // swallowed: protection is opportunistic and must never break persistence.
    public static function protectDirectory(string $directory): void
    {
        if ($directory === '') {
            return;
        }
        if (!is_dir($directory)) {
            @mkdir($directory, 0755, true);
        }
        if (!is_dir($directory) || !is_writable($directory)) {
            return;
        }
        $htaccess = rtrim($directory, '/') . '/.htaccess';
        if (!file_exists($htaccess)) {
            $rules = "# Deny all web access to this data directory (defense in depth).\n"
                . "# The real protection is keeping this directory outside the web root.\n"
                . "<IfModule mod_authz_core.c>\n"
                . "    Require all denied\n"
                . "</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n"
                . "    Order allow,deny\n"
                . "    Deny from all\n"
                . "</IfModule>\n";
            @file_put_contents($htaccess, $rules);
        }
        $index = rtrim($directory, '/') . '/index.html';
        if (!file_exists($index)) {
            @file_put_contents($index, '');
        }
    }

}

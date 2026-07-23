<?php

require '../../vendor/autoload.php';

use VoltCMS\UserAccess\Group;
use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\UserProvider;
use \VoltCMS\UserAccess\GroupProvider;
use \VoltCMS\UserAccess\SCIM;
use \VoltCMS\UserAccess\SessionAuth;

$userProvider = UserProvider::getInstance(array('directory' => '../data/users'));
$groupProvider = GroupProvider::getInstance(array('directory' => '../data/groups'));

if (!$userProvider->exists('userName', 'Administrator')){
    $user = new User();
    $user->setUserName('Administrator');
    $user->setDisplayName('Admin Last');
    $user->setFamilyName('Last');
    $user->setGivenName('Admin');
    $user->setEmail('Administrator@voltcms.com');
    // DEMO ONLY: a hardcoded seed password so the demo has an admin to log in
    // as. Never ship hardcoded credentials in a real deployment.
    $user->setPassword('daze4726DKAU!!!!');
    $user = $userProvider->create($user);
    $group = $groupProvider->read('displayName', 'Administrators');
    $group->addMember($user->getId());
    $groupProvider->update($group);
}

$sessionAuth = SessionAuth::getInstance($userProvider, $groupProvider);

// Resolve the request path relative to this front controller (mirrors how the
// SCIM router strips the script's base path), so the demo's own auth routes can
// be handled here before delegating everything else to the SCIM router.
$scriptDir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '')), '/');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$path = rawurldecode($path === null ? '/' : $path);
if ($scriptDir !== '' && str_starts_with($path, $scriptDir)) {
    $path = substr($path, strlen($scriptDir));
}
$path = '/' . trim($path, '/');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

function sendJson(array $payload, int $status = 200): void
{
    header('Content-Type: application/json', true, $status);
    echo json_encode($payload);
    exit();
}

// GET /auth/session — report login state and hand out the CSRF token the login
// form must echo back.
if ($path === '/auth/session' && $method === 'GET') {
    $loggedIn = $sessionAuth->isLoggedIn();
    $user = $loggedIn ? $sessionAuth->getLoggedInUser() : null;
    sendJson(array(
        'loggedIn' => $loggedIn,
        'userName' => $user ? $user->getUserName() : '',
        'displayName' => $user ? $user->getDisplayName() : '',
        'isAdmin' => $user ? $user->isAdmin() : false,
        'csrfToken' => $sessionAuth->getCsrfToken(),
    ));
}

// POST /auth/login — { userName, password, csrfToken }
if ($path === '/auth/login' && $method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    $body = is_array($body) ? $body : array();
    $userName = $body['userName'] ?? '';
    $password = $body['password'] ?? '';
    $csrfToken = $body['csrfToken'] ?? null;
    $ok = $sessionAuth->login($userName, $password, $csrfToken);
    if (!$ok) {
        sendJson(array('loggedIn' => false, 'detail' => 'Invalid credentials.'), 401);
    }
    $user = $sessionAuth->getLoggedInUser();
    if (!$user || !$user->isAdmin()) {
        // The SCIM API requires an admin; make that explicit at login time.
        $sessionAuth->logout();
        sendJson(array('loggedIn' => false, 'detail' => 'This account is not an administrator.'), 403);
    }
    sendJson(array(
        'loggedIn' => true,
        'userName' => $user->getUserName(),
        'displayName' => $user->getDisplayName(),
        'isAdmin' => true,
    ));
}

// POST /auth/logout
if ($path === '/auth/logout' && $method === 'POST') {
    $sessionAuth->logout();
    sendJson(array('loggedIn' => false));
}

// Everything else goes to the SCIM API with authentication ENFORCED (secure by
// default). The demo UI authenticates via the /auth/login endpoint above and
// then relies on the session cookie for these calls.
$app = new SCIM($userProvider, $groupProvider);
// Optional: enable OAuth Bearer-token auth (how IdPs like Okta / Entra ID
// provision over SCIM) by exporting USERACCESS_SCIM_BEARER_TOKEN before starting
// the server. When set, `Authorization: Bearer <token>` is accepted alongside
// the session login. Use a long, random value and only over HTTPS in production.
$bearerToken = getenv('USERACCESS_SCIM_BEARER_TOKEN');
if ($bearerToken !== false && $bearerToken !== '') {
    $app->setBearerTokens([$bearerToken]);
}
// In production, refuse plaintext HTTP and send HSTS (kept off here because the
// local demo runs over http://localhost):
//     $app->setHttpsPolicy(true);
$app->runRouter();

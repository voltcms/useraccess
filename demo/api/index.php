<?php

require '../../vendor/autoload.php';

use VoltCMS\UserAccess\Group;
use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\UserProvider;
use \VoltCMS\UserAccess\GroupProvider;
use \VoltCMS\UserAccess\SCIM;
use \VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\PasskeyAuth;
use VoltCMS\UserAccess\PasskeyProvider;

$userProvider = UserProvider::getInstance(array('directory' => '../data/users'));
$groupProvider = GroupProvider::getInstance(array('directory' => '../data/groups'));
// Initialized next to the user store, so deleting a user also deletes their
// passkeys.
$passkeyProvider = PasskeyProvider::getInstance(['directory' => '../data/passkeys']);

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

// Passkeys are scoped to a domain (the relying party id) and checked against
// the exact origins the UI is served from. The defaults fit the local demo on
// http://localhost:8000; for anything else export USERACCESS_PASSKEY_RP_ID
// (e.g. example.com) and USERACCESS_PASSKEY_ORIGINS (comma-separated, e.g.
// https://example.com). Browsers only offer passkeys in a secure context:
// https, or http on localhost.
$passkeyAuth = new PasskeyAuth(
    $userProvider,
    $passkeyProvider,
    getenv('USERACCESS_PASSKEY_RP_ID') ?: 'localhost',
    'User Access Demo',
    explode(',', getenv('USERACCESS_PASSKEY_ORIGINS') ?: 'http://localhost:8000')
);
$passkeyAuth->setAuditLog(new AuditLog('../data/audit'));

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

function sendJson(array $payload, int $status = 200): never
{
    header('Content-Type: application/json', true, $status);
    echo json_encode($payload);
    exit();
}

// Answers a successful sign-in, password or passkey alike. The SCIM API needs
// an administrator, so any other account is signed straight back out.
function sendLoginResult(SessionAuth $sessionAuth): never
{
    $user = $sessionAuth->getLoggedInUser();
    if (!$user || !$user->isAdmin()) {
        $sessionAuth->logout();
        sendJson(['loggedIn' => false, 'detail' => 'This account is not an administrator.'], 403);
    }
    sendJson([
        'loggedIn' => true,
        'userName' => $user->getUserName(),
        'displayName' => $user->getDisplayName(),
        'isAdmin' => true,
    ]);
}

// The passkey management endpoints act on the signed-in user's own passkeys.
function requireSessionUser(SessionAuth $sessionAuth): User
{
    $user = $sessionAuth->getLoggedInUser();
    if ($user === null) {
        sendJson(['detail' => 'Sign in first.'], 401);
    }
    return $user;
}

// Turns a PasskeyAuth exception code into a message for the UI. Anything not
// listed is unexpected and gets a generic 500 instead of the raw code.
function sendPasskeyError(Exception $e): never
{
    $errors = [
        'EXCEPTION_INVALID_PASSKEY_NAME' => [400, 'A passkey name may be at most 64 characters long and may not contain line breaks.'],
        'EXCEPTION_PASSKEY_CEREMONY_MISSING' => [400, 'The passkey request expired. Please try again.'],
        'EXCEPTION_PASSKEY_VERIFICATION_FAILED' => [400, 'The passkey could not be verified.'],
        'EXCEPTION_PASSKEY_ALREADY_EXIST' => [409, 'This passkey is already registered.'],
        'EXCEPTION_ENTRY_NOT_EXIST' => [404, 'That passkey does not exist.'],
    ];
    error_log('Passkey request failed: ' . $e->getMessage());
    [$status, $detail] = $errors[$e->getMessage()] ?? [500, 'The passkey request failed.'];
    sendJson(['detail' => $detail], $status);
}

function readJsonBody(): array
{
    $body = json_decode(file_get_contents('php://input'), true);
    return is_array($body) ? $body : [];
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
    sendLoginResult($sessionAuth);
}

// POST /auth/logout
if ($path === '/auth/logout' && $method === 'POST') {
    $sessionAuth->logout();
    sendJson(array('loggedIn' => false));
}

// POST /auth/passkey/login/options — start a passkey sign-in; the response is
// what navigator.credentials.get() takes.
if ($path === '/auth/passkey/login/options' && $method === 'POST') {
    sendJson($passkeyAuth->getLoginOptions());
}

// POST /auth/passkey/login — { credential, csrfToken }, where credential is
// the PublicKeyCredential navigator.credentials.get() returned, as JSON.
if ($path === '/auth/passkey/login' && $method === 'POST') {
    $body = readJsonBody();
    $credential = json_encode($body['credential'] ?? null);
    if (!$sessionAuth->loginWithPasskey($passkeyAuth, $credential, $body['csrfToken'] ?? null)) {
        sendJson(['loggedIn' => false, 'detail' => 'The passkey could not be verified.'], 401);
    }
    sendLoginResult($sessionAuth);
}

// POST /auth/passkey/register/options — start registering a passkey for the
// signed-in user; the response is what navigator.credentials.create() takes.
if ($path === '/auth/passkey/register/options' && $method === 'POST') {
    $user = requireSessionUser($sessionAuth);
    sendJson($passkeyAuth->getRegistrationOptions($user));
}

// POST /auth/passkey/register — { credential, name }
if ($path === '/auth/passkey/register' && $method === 'POST') {
    $user = requireSessionUser($sessionAuth);
    $body = readJsonBody();
    try {
        $passkey = $passkeyAuth->register($user, json_encode($body['credential'] ?? null), (string) ($body['name'] ?? ''));
    } catch (Exception $e) {
        sendPasskeyError($e);
    }
    sendJson($passkey->toArray(), 201);
}

// GET /auth/passkeys — the signed-in user's passkeys.
if ($path === '/auth/passkeys' && $method === 'GET') {
    $user = requireSessionUser($sessionAuth);
    $passkeys = [];
    foreach ($passkeyAuth->getPasskeys($user) as $passkey) {
        $passkeys[] = $passkey->toArray();
    }
    sendJson(['passkeys' => $passkeys]);
}

// DELETE /auth/passkeys/{id}
if (preg_match('#^/auth/passkeys/([a-f0-9-]{36})$#', $path, $matches) && $method === 'DELETE') {
    $user = requireSessionUser($sessionAuth);
    try {
        $passkeyAuth->deletePasskey($user, $matches[1]);
    } catch (Exception $e) {
        sendPasskeyError($e);
    }
    http_response_code(204);
    exit();
}

// Everything else goes to the SCIM API with authentication ENFORCED (secure by
// default). The demo UI authenticates via the /auth/login endpoint above and
// then relies on the session cookie for these calls.
$app = new SCIM($userProvider, $groupProvider);
// Record admin actions (create/update/delete of users and groups) to an
// append-only JSON-Lines audit log. Kept alongside the demo data (outside the
// api/ web root); a deny-all .htaccess is dropped in automatically.
$app->setAuditLogDirectory('../data/audit');
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

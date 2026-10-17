# VoltCMS UserAccess

[![CI](https://github.com/voltcms/useraccess/actions/workflows/ci.yml/badge.svg)](https://github.com/voltcms/useraccess/actions/workflows/ci.yml)

A small, dependency‑light **PHP 8 library for user and access management**. It stores
users and groups in a flat‑file JSON database and exposes them through a **SCIM 2.0**
(RFC 7643/7644) REST API, plus session, passkey (WebAuthn), HTTP Basic, and OAuth Bearer
authentication helpers for protecting pages and provisioning from an identity provider (Okta,
Entra ID, …).

It is published as a Composer package (PSR‑4 namespace `VoltCMS\UserAccess\` → `src/`) and is
meant to be **embedded in a host application**, not run standalone. The `demo/` directory shows
a complete, fully‑authenticated integration.

> Working in this repo with an AI assistant? Read [`CLAUDE.md`](CLAUDE.md) for the deep
> architecture/conventions guide, and the [For AI agents](#for-ai-agents-integrating-into-another-project)
> section below for a copy‑pasteable integration recipe.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [The SCIM API](#the-scim-api)
- [Custom user attributes](#custom-user-attributes)
- [Authentication](#authentication)
- [Passkeys](#passkeys)
- [Security & hardening](#security--hardening)
- [Configuration reference](#configuration-reference)
- [The demo](#the-demo)
- [Testing & CI](#testing--ci)
- [Deploying to production](#deploying-to-production)
- [For AI agents](#for-ai-agents-integrating-into-another-project)
- [Not yet implemented](#not-yet-implemented)
- [License](#license)

---

## Features

- **SCIM 2.0 REST API** for Users and Groups: GET (list + single), POST, PUT, PATCH, DELETE,
  plus discovery (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`) and `/Me`.
  Responses use `application/scim+json`.
- **Three authentication modes**, usable together:
  - PHP **session** login (CSRF‑protected, session‑fixation hardened), by password or by
    **passkey**;
  - HTTP **Basic**;
  - OAuth **Bearer** token (for IdP provisioning).
- **Secure by default** — the SCIM router requires an authenticated administrator unless you
  explicitly opt out.
- **Security hardening built in**: bcrypt password hashing with an 8–72 char policy,
  shared‑storage brute‑force lockout, optional HTTPS enforcement + HSTS, proxy‑aware HTTPS
  detection, data‑directory web‑access protection, and an append‑only **audit log** of admin
  actions.
- **Passkeys (WebAuthn)** — username‑less, phishing‑resistant sign‑in built on
  [web-auth/webauthn-lib](https://github.com/web-auth/webauthn-lib), with self‑service
  registration and removal.
- **Custom user attributes** — store host‑defined fields on a user; they are exposed over SCIM
  through a schema extension.
- **No SQL** — a flat‑file JSON store (`voltcms/filedb`) with a process‑wide write mutex.
- Small, framework‑light, easy to read and audit.

## Requirements

- **PHP ≥ 8.2** (developed against 8.4) with the `openssl` extension (passkey signatures).
- **Composer 2**.
- A web server that routes unknown paths to a front controller and passes the `Authorization`
  header through (Apache rewrite provided in `demo/api/.htaccess`; nginx `try_files` works too).

## Installation

This package is distributed via its Git repository. Add it to your project's `composer.json`:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/voltcms/useraccess" }
    ],
    "require": {
        "voltcms/useraccess": "^2.0"
    }
}
```

```bash
composer update voltcms/useraccess
```

Or, working inside this repository directly:

```bash
composer install      # install dependencies into vendor/
composer test         # run the PHPUnit suite
```

## Quick start

A minimal, **production‑oriented** front controller. Point your web server so every request
under `/scim/...` reaches this file.

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use VoltCMS\UserAccess\UserProvider;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\SCIM;

// 1. Persistence — keep the data directory OUTSIDE the web root (see Security).
$userProvider  = UserProvider::getInstance(['directory' => '/var/lib/voltcms/users']);
$groupProvider = GroupProvider::getInstance(['directory' => '/var/lib/voltcms/groups']);

// 2. The SCIM app. Authentication is ENFORCED by default (admin required).
$app = new SCIM($userProvider, $groupProvider);

// 3. Recommended production hardening:
$app->setHttpsPolicy(true);                       // refuse plaintext HTTP, send HSTS
$app->setAuditLogDirectory('/var/log/voltcms');   // audit admin actions
$app->setBearerTokens([getenv('SCIM_BEARER')]);   // let your IdP provision via Bearer

// 4. Route the request.
$app->runRouter();
```

The very first call to `GroupProvider::getInstance()` auto‑creates the **`Administrators`**
group. Membership in it == administrator. Seed your first admin once (see the demo's
`demo/api/index.php` for an example), then manage everyone else through the API or your host UI.

## Architecture

| Piece | Responsibility |
|-------|----------------|
| `User`, `Group` | Plain entities. Field validation lives in setters; `toSCIM()`/`fromSCIM()` convert to/from SCIM. |
| `UserProvider`, `GroupProvider` | Singleton persistence (CRUD) over `voltcms/filedb`. Depend on the `*ProviderInterface`. |
| `SCIM` | The SCIM 2.0 router + request handlers — the main integration point. |
| `SessionAuth` | Session login/logout (password or passkey), CSRF, group enforcement. |
| `Passkey`, `PasskeyProvider` | A user's WebAuthn credentials and their FileDB store. |
| `PasskeyAuth` | Passkey registration and sign‑in ceremonies (wraps webauthn-lib). |
| `HeaderAuth` / `BearerAuth` | Stateless HTTP Basic / OAuth Bearer checks. |
| `LoginThrottle` | Shared brute‑force lockout (identifier + IP). |
| `Lock` | Process‑wide reentrant write mutex for the flat‑file store. |
| `AuditLog` | Append‑only JSON‑Lines audit trail. |
| `Utils` | `isHttps()`, `protectDirectory()`, base64url, page‑protection helpers. |

- **IDs** are UUIDs. `_id`, `_created`, `_modified` are managed metadata.
- **Passwords** are hashed with `password_hash(PASSWORD_DEFAULT)`; the hash is stored on disk
  but **stripped from all API responses**.
- **Writes are serialized** through `Lock::exclusive()`; reads are not locked.

## The SCIM API

All routes are under `/scim`. UUIDs are matched strictly. Responses are
`application/scim+json`; errors use the SCIM `Error` schema.

| Method | Path | Description |
|-------:|------|-------------|
| GET | `/scim/users` | List users (`startIndex`, `count`, single `attribute eq "value"` filter) |
| POST | `/scim/users` | Create a user |
| GET | `/scim/users/{uuid}` | Read a user |
| PUT | `/scim/users/{uuid}` | Replace a user |
| PATCH | `/scim/users/{uuid}` | PatchOp (`add`/`replace`/`remove`) |
| DELETE | `/scim/users/{uuid}` | Delete a user (also strips them from every group) |
| GET/POST/… | `/scim/groups[...]` | Same verbs for groups (members via PATCH) |
| GET | `/scim/ServiceProviderConfig` | Capabilities (singular + legacy plural) |
| GET | `/scim/ResourceTypes[/{id}]` | Resource‑type discovery |
| GET | `/scim/Schemas[/{urn}]` | Schema discovery |
| GET | `/scim/Me` | The authenticated user (404 for a Bearer service token) |

Example (Bearer‑authenticated create):

```bash
curl -X POST https://host/scim/users \
  -H "Authorization: Bearer $SCIM_BEARER" \
  -H "Content-Type: application/scim+json" \
  -d '{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "jdoe",
        "password": "correcthorsebattery",
        "name": { "givenName": "Jane", "familyName": "Doe" },
        "emails": [{ "value": "jane@example.com" }]
      }'
```

Notes:
- **`active` on write**: omit it and create defaults to `active: true`; a `PUT` that omits it
  preserves the current value. Only an explicit boolean/int changes it.
- **Pagination**: 1‑based `startIndex` + `count`; `totalResults` is the full filtered count.
- **Filtering**: a single `attribute eq "value"` expression, for both users and groups.

## Custom user attributes

A host application can store its own fields on a user — a department, an employee number, a
tenant id — without changing this library. They are persisted next to the core fields and are
carried over SCIM in the extension schema
`urn:ietf:params:scim:schemas:extension:voltcms:2.0:User` (`User::CUSTOM_SCHEMA`), which is
how RFC 7643 §3.3 says non‑core attributes should travel. The extension is advertised by
`/scim/ResourceTypes/User` (`schemaExtensions`) and `/scim/Schemas`.

Rules:
- **Names** must start with a letter and may contain letters, digits, `-` and `_`, up to 64
  characters. Lookups are case‑insensitive (SCIM attribute names are), so `Department` and
  `department` are one attribute.
- **Reserved names** — anything that collides with a core field (`userName`, `passwordHash`,
  `active`, …) is rejected, so a custom attribute can never overwrite managed state.
- **Values** are JSON‑simple: a string, number, boolean, `null`, or a flat list of those.
  Nested objects are rejected.
- **Omission preserves**: a `PUT` that does not mention the extension leaves the stored custom
  attributes alone (the same rule as `active`). Send an empty extension object to clear them.

In PHP:

```php
$user->setCustomAttribute('department', 'Engineering');
$user->setCustomAttribute('costCenters', ['de-01', 'de-02']);
$user->getCustomAttribute('DEPARTMENT');   // 'Engineering' — case-insensitive
$user->hasCustomAttribute('tenant');       // false
$user->removeCustomAttribute('costCenters');
$user->setCustomAttributes(['tenant' => 'acme']);  // replaces the whole set
$user->clearCustomAttributes();
$userProvider->update($user);
```

Over SCIM:

```bash
# Create with custom attributes
curl -X POST https://host/scim/users \
  -H "Authorization: Bearer $SCIM_BEARER" \
  -H "Content-Type: application/scim+json" \
  -d '{
        "schemas": [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:voltcms:2.0:User"
        ],
        "userName": "jdoe",
        "password": "correcthorsebattery",
        "urn:ietf:params:scim:schemas:extension:voltcms:2.0:User": {
          "department": "Engineering",
          "employeeNumber": 4711
        }
      }'
```

PATCH paths (both the fully qualified URN form of RFC 7644 §3.5.2 and a `customAttributes.…`
alias are accepted):

| `op` | `path` | Effect |
|------|--------|--------|
| add / replace | `urn:…:extension:voltcms:2.0:User:department` | Set one attribute |
| add / replace | `customAttributes.department` | Same, alias form |
| add | `urn:…:extension:voltcms:2.0:User` | Merge an object into the set |
| replace | `urn:…:extension:voltcms:2.0:User` | Replace the whole set |
| remove | `urn:…:extension:voltcms:2.0:User:department` | Remove one attribute |
| remove | `urn:…:extension:voltcms:2.0:User` | Remove all custom attributes |

Responses only carry the extension (and list its URN in `schemas`) when the user actually has
custom attributes. Filtering on custom attributes is not supported.

## Authentication

The SCIM router accepts **any** of the following as an administrator (checked in this order:
session → HTTP Basic → Bearer):

**1. Session** — for a browser UI. Drive it with `SessionAuth`:

```php
$session = SessionAuth::getInstance($userProvider, $groupProvider);
$session->login($userNameOrEmail, $password, $csrfToken); // 429 when locked out
$session->isLoggedIn();
$session->getCsrfToken();   // echo into your login form / X-CSRF-Token
$session->logout();
```

Cookies are `httponly` + `samesite=Strict` (and `secure` over HTTPS); the session id is
regenerated on login. `SessionAuth` also protects arbitrary pages:
`enforceLoggedIn()`, `isMemberOfGroup($g)`, `enforceMemberOfGroup($g)`.

**2. HTTP Basic** — `Authorization: Basic base64(user:pass)`. Requires the web server to pass
the `Authorization` header through. Stateless; throttled by `LoginThrottle`.

**3. OAuth Bearer** — for machine provisioning from an IdP. Enable with configured tokens:

```php
$app->setBearerTokens(['a-long-random-secret', 'another-during-rotation']);
```

A valid `Authorization: Bearer <token>` authorizes the request as the provisioning service
(full admin, no per‑user lookup) — matching how Okta/Entra provision over SCIM. Tokens are
stored only as SHA‑256 hashes and compared in constant time. `ServiceProviderConfig`
advertises `oauthbearertoken` once configured.

## Passkeys

Passkeys let users sign in to the **session** with a fingerprint, face or device PIN instead of
a password. The WebAuthn ceremonies are delegated to
[web-auth/webauthn-lib](https://github.com/web-auth/webauthn-lib), the framework‑independent
library of [webauthn-framework](https://github.com/web-auth/webauthn-framework); UserAccess adds
storage, session integration and the policy below.

```php
use VoltCMS\UserAccess\PasskeyAuth;
use VoltCMS\UserAccess\PasskeyProvider;

$passkeyProvider = PasskeyProvider::getInstance(['directory' => '/var/lib/voltcms/passkeys']);
$session  = SessionAuth::getInstance($userProvider, $groupProvider); // holds the challenges
$passkeys = new PasskeyAuth(
    $userProvider,
    $passkeyProvider,
    'example.com',             // relying party id: the domain passkeys are scoped to
    'Example',                 // name the browser shows
    ['https://example.com']    // exact origins the UI is served from
);
$passkeys->setAuditLog(new AuditLog('/var/log/voltcms'));   // optional
```

Each ceremony takes two requests to endpoints you define (`demo/api/index.php` has all of them):

| Step | Server | Browser |
|------|--------|---------|
| Register (signed in) | `$passkeys->getRegistrationOptions($user)` | `navigator.credentials.create({ publicKey })` |
| | `$passkeys->register($user, $credentialJson, $name)` → `Passkey` | |
| Sign in | `$passkeys->getLoginOptions()` | `navigator.credentials.get({ publicKey })` |
| | `$session->loginWithPasskey($passkeys, $credentialJson, $csrfToken)` → `bool` | |
| Manage | `$passkeys->getPasskeys($user)`, `$passkeys->deletePasskey($user, $id)` | |

Options come back in WebAuthn's JSON form (binary values as unpadded base64url). Convert them
to `ArrayBuffer`s for `navigator.credentials` and send the credential back serialized the way
`credential.toJSON()` does; `demo/ui/js/useraccess.js` has small helpers for both.

- **Username‑less sign‑in.** The login options name no credentials: the authenticator offers
  its discoverable passkeys and the one used identifies the account, so the endpoint reveals
  nothing about which users exist. Registration therefore requires a discoverable credential.
- **User verification is required** (biometric or PIN) in both ceremonies, because a passkey
  replaces the password rather than adding a second factor.
- **Single‑use challenges** live in the session and expire with the ceremony (5 minutes by
  default). A registration started for one user cannot be finished for another.
- **Relying party id and origins are configuration**, never derived from the `Host` header —
  that is what keeps passkeys phishing‑resistant.
- **Clone detection:** the signature counter is stored, and one that goes backwards fails the
  sign‑in. An inactive user's passkeys stop working.
- **Deleting a user deletes their passkeys**, provided `PasskeyProvider` is initialized in the
  same bootstrap as `UserProvider`.
- Like Bearer tokens, passkey sign‑in is not run through `LoginThrottle`: there is no secret to
  guess.
- **Registration trusts whoever holds the session.** A hijacked session could add the
  attacker's own passkey and keep access past a password change, so consider asking for the
  password again before `getRegistrationOptions()`. Registrations and removals are recorded
  when an audit log is set.

Failures throw `EXCEPTION_PASSKEY_VERIFICATION_FAILED` (the reason goes to the error log),
`EXCEPTION_PASSKEY_CEREMONY_MISSING` (no pending or an expired challenge),
`EXCEPTION_INVALID_PASSKEY_NAME`, or `EXCEPTION_ENTRY_NOT_EXIST` from `deletePasskey()`.
Browsers offer WebAuthn only in a secure context: serve the UI over HTTPS, or from
`http://localhost` during development.

## Security & hardening

| Area | What you get | How |
|------|--------------|-----|
| **Auth default** | Secure by default (admin required) | `new SCIM($u, $g)` — pass `false` only to opt out |
| **Transport** | Refuse plaintext HTTP, send HSTS | `$app->setHttpsPolicy(true)` (proxy‑aware via `X-Forwarded-Proto`) |
| **Passwords** | bcrypt, 8–72 char policy | enforced in `User::validatePassword` |
| **Brute force** | Lockout by identifier + IP, survives cookie drops | `LoginThrottle` (429 after `maxLoginAttempts` within 900s) |
| **Passkeys** | Phishing‑resistant, user‑verified sign‑in; single‑use challenges; clone detection | `PasskeyAuth` + `SessionAuth::loginWithPasskey()` |
| **Data at rest** | Deny‑all `.htaccess` + `index.html` dropped into data dirs | `Utils::protectDirectory()`, automatic |
| **Audit** | Append‑only JSON‑Lines of every admin mutation | `$app->setAuditLogDirectory($dir)` |
| **Concurrency** | Serialized writes, atomic user‑delete | `Lock::exclusive()`, automatic |
| **Info leak** | No stack traces or internal codes to clients | global handler + `messageForException()` |

**The single most important deployment rule:** the on‑disk JSON documents contain bcrypt
password hashes and PII. **Keep the data directory outside the web root.** The automatic
deny‑all `.htaccess` is Apache‑only defense‑in‑depth; on nginx add:

```nginx
location ~ /data/ { deny all; return 404; }
```

## Configuration reference

```php
// Providers (singletons)
UserProvider::getInstance(['directory' => '/path/out/of/webroot/users']);
GroupProvider::getInstance(['directory' => '/path/out/of/webroot/groups']);

// SCIM
$app = new SCIM($userProvider, $groupProvider, $enforceAuthentication = true);
$app->setHttpsPolicy($requireHttps = true, $hstsMaxAge = 31536000, $includeSubDomains = true);
$app->setBearerTokens(['token1', 'token2']);
$app->setAuditLogDirectory('/var/log/voltcms');   // or setAuditLog(new AuditLog($dir))
$app->runRouter();

// Session tuning
SessionAuth::getInstance($userProvider, $groupProvider, $maxLoginAttempts = 10, $refreshTime = 60);

// Passkeys
PasskeyProvider::getInstance(['directory' => '/path/out/of/webroot/passkeys']);
$passkeys = new PasskeyAuth($userProvider, $passkeyProvider, $rpId, $rpName, $allowedOrigins, $timeoutMs = 300000);
$passkeys->setAuditLog(new AuditLog('/var/log/voltcms'));
```

## The demo

A complete, fully‑authenticated Bootstrap UI + wired API.

```bash
composer install
npm install                     # front-end deps for the demo UI
cd demo/api && php -S localhost:8000   # behind an Apache-style rewrite to index.php
# open demo/ui/index.html (served so /api and /ui are siblings)
```

The demo seeds an `Administrator` user (hardcoded password — **demo only**), enforces auth,
exposes `/auth/session|login|logout`, and gates the UI behind a login form. Set
`USERACCESS_SCIM_BEARER_TOKEN` to also allow Bearer provisioning. It logs to `demo/data/audit`.

Passkeys work out of the box at `http://localhost:8000`: sign in, open **Passkeys** to add one,
then use **Sign in with a passkey**. The endpoints are `/auth/passkey/login/options`,
`/auth/passkey/login`, `/auth/passkey/register/options`, `/auth/passkey/register`,
`GET /auth/passkeys` and `DELETE /auth/passkeys/{id}`. On any other host, export
`USERACCESS_PASSKEY_RP_ID` (e.g. `example.com`) and `USERACCESS_PASSKEY_ORIGINS`
(comma‑separated, e.g. `https://example.com`).

## Testing & CI

```bash
composer test        # PHPUnit
composer phpstan      # static analysis (level 2, src/)
composer phpcs        # coding-standard check
```

CI (`.github/workflows/ci.yml`) runs the suite + PHPStan + PHP_CodeSniffer on PHP 8.4 and a
`php -l` lint matrix on 8.2/8.3/8.4 for every push and PR. Always run `composer test` before
committing.

## Deploying to production

1. **Data directory outside the web root** (+ nginx `deny` if not on Apache).
2. **Keep authentication enforced** — `new SCIM($u, $g)` (never pass `false`).
3. `**$app->setHttpsPolicy(true)**` and terminate TLS (works behind a proxy setting
   `X-Forwarded-Proto`).
4. `**$app->setAuditLogDirectory(...)**` to a path outside the web root.
5. For IdP provisioning, `**$app->setBearerTokens([...])**` with a long random secret from
   the environment; rotate by listing two.
6. Never ship hardcoded credentials (the demo's seed is demo‑only).
7. For passkeys, set the relying party id to your domain and list the exact HTTPS origins your
   UI is served from. Changing the domain later orphans existing passkeys.
8. Back up the data directory (see [Not yet implemented](#not-yet-implemented)).

## For AI agents (integrating into another project)

This section is a self‑contained recipe for an AI coding assistant asked to add UserAccess to
another codebase. Also read [`CLAUDE.md`](CLAUDE.md) for conventions if you will modify this
library.

**Goal:** expose a secure SCIM 2.0 user/group API and/or protect pages in a host app.

**Steps:**

1. **Add the dependency** via a VCS repository (see [Installation](#installation)); require
   `voltcms/useraccess: ^2.0`. Run `composer update voltcms/useraccess`.
2. **Choose a data directory OUTSIDE the web root** (e.g. `/var/lib/<app>/useraccess`). This is
   mandatory — the files hold bcrypt hashes + PII.
3. **Create a front controller** that your web server routes all `/scim/...` (and any
   `/auth/...`) requests to. Start from [Quick start](#quick-start). Ensure the server passes
   the `Authorization` header through (Apache: see `demo/api/.htaccess`).
4. **Keep `new SCIM($u, $g)` enforced.** Only pass `false` for a throwaway local demo, and say
   so loudly.
5. **Pick the auth mode(s)** for the host:
   - Browser UI → `SessionAuth` login flow (see `demo/api/index.php` + `demo/ui/js/useraccess.js`
     for a working reference, including CSRF), optionally with passkeys via `PasskeyAuth`
     (see [Passkeys](#passkeys)).
   - IdP provisioning (Okta/Entra) → `setBearerTokens([...])` from an env var.
   - Server‑to‑server scripts → HTTP Basic or Bearer.
6. **Turn on hardening**: `setHttpsPolicy(true)` in production, `setAuditLogDirectory(...)`,
   and add the nginx `deny` rule if not on Apache.
7. **Seed one admin** once (create a `User`, add it to the `Administrators` group), then never
   hardcode credentials again.
8. **Protect host pages** (optional) with `SessionAuth::enforceLoggedIn()` /
   `enforceMemberOfGroup('SomeGroup')`, or `Utils::protectPage(...)`.

**Conventions to follow if you modify the library:** match the plain‑PHP style (4‑space indent,
getters/setters, validation in setters, providers are singletons); throw domain errors as
`\Exception` with stable string codes; keep new mutations inside `Lock::exclusive()` and add a
`writeAudit(...)` on their success path; keep `passwordHash` out of any response; run
`composer test`, `composer phpstan`, and `composer phpcs` before finishing.

**Things not to do:** don't run the SCIM API over plaintext HTTP with real data; don't put the
data directory in the web root; don't disable authentication in production; don't add hardcoded
passwords; don't leak `passwordHash` or raw `EXCEPTION_*` codes in new responses.

## Not yet implemented

Tracked in [`TODO.md`](TODO.md); contributions welcome:

- **Backup / restore** tooling for the flat‑file store (deferred to a follow‑up).
- SCIM **Bulk**, **sort**, and **complex filtering** (a single `attribute eq "value"` is
  supported today).
- The flat‑file store serializes writers safely but does not scale to high write concurrency;
  a transactional backend would be needed there.

## License

ISC — see [`LICENSE.md`](LICENSE.md).

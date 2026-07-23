# VoltCMS UserAccess

[![CI](https://github.com/voltcms/useraccess/actions/workflows/ci.yml/badge.svg)](https://github.com/voltcms/useraccess/actions/workflows/ci.yml)

A small, dependency‑light **PHP 8 library for user and access management**. It stores
users and groups in a flat‑file JSON database and exposes them through a **SCIM 2.0**
(RFC 7643/7644) REST API, plus session, HTTP Basic, and OAuth Bearer authentication
helpers for protecting pages and provisioning from an identity provider (Okta, Entra ID, …).

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
- [Authentication](#authentication)
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
  - PHP **session** login (CSRF‑protected, session‑fixation hardened);
  - HTTP **Basic**;
  - OAuth **Bearer** token (for IdP provisioning).
- **Secure by default** — the SCIM router requires an authenticated administrator unless you
  explicitly opt out.
- **Security hardening built in**: bcrypt password hashing with an 8–72 char policy,
  shared‑storage brute‑force lockout, optional HTTPS enforcement + HSTS, proxy‑aware HTTPS
  detection, data‑directory web‑access protection, and an append‑only **audit log** of admin
  actions.
- **No SQL** — a flat‑file JSON store (`voltcms/filedb`) with a process‑wide write mutex.
- Small, framework‑light, easy to read and audit.

## Requirements

- **PHP ≥ 8.2** (developed against 8.4).
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
| `SessionAuth` | Session login/logout, CSRF, group enforcement. |
| `HeaderAuth` / `BearerAuth` | Stateless HTTP Basic / OAuth Bearer checks. |
| `LoginThrottle` | Shared brute‑force lockout (identifier + IP). |
| `Lock` | Process‑wide reentrant write mutex for the flat‑file store. |
| `AuditLog` | Append‑only JSON‑Lines audit trail. |
| `Utils` | `isHttps()`, `protectDirectory()`, page‑protection helpers. |

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

## Security & hardening

| Area | What you get | How |
|------|--------------|-----|
| **Auth default** | Secure by default (admin required) | `new SCIM($u, $g)` — pass `false` only to opt out |
| **Transport** | Refuse plaintext HTTP, send HSTS | `$app->setHttpsPolicy(true)` (proxy‑aware via `X-Forwarded-Proto`) |
| **Passwords** | bcrypt, 8–72 char policy | enforced in `User::validatePassword` |
| **Brute force** | Lockout by identifier + IP, survives cookie drops | `LoginThrottle` (429 after `maxLoginAttempts` within 900s) |
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
7. Back up the data directory (see [Not yet implemented](#not-yet-implemented)).

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
     for a working reference, including CSRF).
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

Tracked in [`CLAUDE.md`](CLAUDE.md); contributions welcome:

- **Backup / restore** tooling for the flat‑file store (deferred to a follow‑up).
- SCIM **Bulk**, **sort**, and **complex filtering** (a single `attribute eq "value"` is
  supported today).
- The flat‑file store serializes writers safely but does not scale to high write concurrency;
  a transactional backend would be needed there.

## License

ISC — see [`LICENSE.md`](LICENSE.md).

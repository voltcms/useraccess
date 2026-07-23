# CLAUDE.md

Guidance for AI assistants (and humans) working in the **VoltCMS UserAccess** repository.

## What this project is

`voltcms/useraccess` is a small, dependency-light **PHP 8 library for user and access
management**. It stores users and groups in a flat-file JSON database and exposes them
through a **SCIM 2.0** (System for Cross-domain Identity Management, RFC 7643/7644) REST
API. It also provides session-based and HTTP-Basic authentication helpers intended to
protect pages in a host application (VoltCMS).

It is published as a Composer package (`type: project`, PSR-4 namespace
`VoltCMS\UserAccess\` → `src/`) and is meant to be embedded in a host app, not run
standalone. The `demo/` directory shows a minimal working integration.

## Repository layout

```
src/                       # The library (PSR-4: VoltCMS\UserAccess\)
  User.php                 # User entity: attributes, password hashing, SCIM (de)serialization
  UserProvider.php         # Singleton persistence for users, backed by FileDB
  UserProviderInterface.php
  Group.php                # Group entity: members, SCIM (de)serialization
  GroupProvider.php        # Singleton persistence for groups; auto-creates "Administrators"
  GroupProviderInterface.php
  SCIM.php                 # SCIM 2.0 REST router + request handlers (the main entry point)
  SessionAuth.php          # Singleton PHP-session login/logout, CSRF, group enforcement
  HeaderAuth.php           # Stateless HTTP Basic auth check
  BearerAuth.php           # Stateless OAuth Bearer-token check (static provisioning tokens)
  Sanitizer.php            # String/array sanitization + validation regexes
  Lock.php                 # Process-wide reentrant advisory write mutex (flock) for FileDB
  LoginThrottle.php        # Shared-storage brute-force lockout (identifier + IP keyed)
  AuditLog.php             # Append-only JSON-Lines audit log of admin mutations
  Utils.php                # Page-protection / content-visibility helpers + isHttps/protectDirectory
  RestApp.php              # Legacy/experimental router — ENTIRELY COMMENTED OUT, not used
tests/                     # PHPUnit tests
  UserTest.php             # User entity unit test
  UserProviderTest.php     # Full provider + SessionAuth integration test (uses real FileDB)
  SCIMTest.php             # SCIM handler tests using mocked providers
demo/
  api/index.php            # Wires providers + SCIM together; seeds an Administrator user
  api/.htaccess            # Apache rewrite to front-controller + Authorization passthrough
  ui/                      # Bootstrap 5 + simple-datatables single-page admin UI (vanilla JS)
composer.json              # PHP deps, autoload, `build` and `test` scripts
phpunit.xml                # PHPUnit config (suite = ./tests, coverage source = ./src)
package.json               # Front-end deps for the demo UI only (bootstrap, simple-datatables)
"scim test.paw"            # Paw/RapidAPI request collection for manual SCIM testing
```

## Setup, build & test

Requires **PHP ^8** (developed against 8.4) and **Composer 2**.

```bash
composer install            # install PHP deps into vendor/ (gitignored)
composer test               # run the PHPUnit suite  -> ./vendor/bin/phpunit
composer run build          # composer update with optimized/authoritative autoloader
./vendor/bin/phpunit tests/UserProviderTest.php   # run a single test file
```

Front-end deps for the demo UI (optional):

```bash
npm install                 # installs bootstrap + simple-datatables into node_modules/
```

Run the demo API locally (from `demo/api`, needs an Apache-style rewrite or a router that
sends everything to `index.php`; note it expects `../../vendor/autoload.php`):

```bash
php -S localhost:8000        # then point the demo UI's fetch base at /api/scim/...
```

**CI** runs on GitHub Actions (`.github/workflows/ci.yml`): a `test` job installs deps and
runs `composer test` on PHP 8.4 (PHPUnit 13 requires 8.4.1+), and a `lint` job `php -l`s
`src/` + `demo/` across PHP 8.2/8.3/8.4 to guard the package's advertised floor. Static
analysis (PHPStan/Psalm) and a coding-standard check are not wired up yet. Always run
`composer test` yourself before considering a change done.

## Core architecture & conventions

### Entities vs. Providers
- **Entities** (`User`, `Group`) are plain PHP objects. They hold private fields with
  `get*/set*` accessors, know how to convert to/from a SCIM array (`toSCIM()` /
  `fromSCIM()` / `setAttributes()` / `getAttributes()`), and enforce field-level
  validation inside their setters (e.g. `User::setEmail` uses `FILTER_VALIDATE_EMAIL`,
  `setUserName` uses `Sanitizer::REGEX_NAME`).
- **Providers** (`UserProvider`, `GroupProvider`) are the persistence layer. Both are
  **singletons** (`getInstance(?array $config)`) wrapping a `VoltCMS\FileDB\FileDB`
  instance rooted at `$config['directory']` (defaults to `data`). They expose a uniform
  CRUD surface: `exists / read / create / readAll / find / update / delete / deleteAll`.
  Both implement their respective `*ProviderInterface`, so callers should depend on the
  interface, not the concrete class (SCIM does exactly this).

### Persistence model
- Storage is **flat-file JSON via FileDB** — there is no SQL database. Each entity is a
  document; `_id`, `_created`, `_modified` are managed metadata (underscored).
- IDs are UUIDs. SCIM routes match them with a strict UUID regex.
- `find($attribute, $value)` delegates to FileDB's attribute query; `read('id', ...)`
  is a direct key lookup. IDs are always lowercased/trimmed before lookup.
- **Writes are serialized.** Every mutating provider method (`create/update/delete/
  deleteAll`) runs inside `Lock::exclusive()`, a reentrant `flock` mutex, since FileDB has
  no locking. Reads are not locked. Keep new mutations inside the lock, and rely on its
  reentrancy for cross-provider sequences (e.g. user-delete updating groups).

### SCIM layer (`SCIM.php`)
- `SCIM` is the primary integration point. Construct it with a user provider and a group
  provider, then call `runRouter()`. It uses **`bramus/router`** to map
  `/scim/users`, `/scim/users/{uuid}`, `/scim/groups`, `/scim/groups/{uuid}`, and
  `/scim/ServiceProviderConfigs` to handler methods.
- Supported verbs: **GET (list + single), POST (create), PUT (replace), PATCH, DELETE**.
  `patchUser` / `patchGroup` implement SCIM PatchOp (`op` = add / replace / remove).
  Users support attribute paths (`userName`, `displayName`, `name.familyName`/`givenName`,
  `active`, `password`, `emails`) plus a pathless replace whose value is an attribute
  object. Groups support `members` (add / replace / remove, including
  `members[value eq "uuid"]` and a bare `remove` that clears all) and `displayName`.
  `ServiceProviderConfig` advertises `patch.supported = true`.
- Responses are hand-built SCIM JSON. Note the consistent output idiom:
  `preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES))`
  strips control characters. Keep this pattern when adding handlers.
- Errors go through `throwError($status, $detail)`, which emits a SCIM
  `urn:ietf:params:scim:api:messages:2.0:Error` body and `exit()`s. Many validation
  failures call `exit($this->throwError(...))`. Handlers set HTTP status via the third
  arg of `header(..., true, $code)`.
- Payload validation lives in `parseUserPayload` / `parseGroupPayload` (schema presence,
  required `userName`/`displayName`, type-checking of optional SCIM fields, uniqueness).
- `enforceAuthentication` (**default true — secure by default**) gates the whole router:
  it requires a logged-in **admin** session user, HTTP Basic credentials for an admin, OR
  a valid Bearer token (`setBearerTokens()`). It is the **third constructor argument**, so `new SCIM($userProvider,
  $groupProvider)` is authenticated; a caller must explicitly opt out with
  `new SCIM($userProvider, $groupProvider, false)`. The demo opts out (its static UI has
  no login flow) with a loud DEMO-ONLY warning — never do that in production.
- **Transport security is opt-in**: `setHttpsPolicy(bool $requireHttps = true, int
  $hstsMaxAge = 31536000, bool $includeSubDomains = true)` makes `runRouter()` refuse
  plaintext HTTP (SCIM 403, before auth) and emit HSTS over HTTPS. Off by default. Runs
  first in `runRouter()` so credentials are never processed over http.
- **Error messages are client-safe**: PATCH/PUT/create map domain codes to friendly text
  via `messageForException()`; handlers never echo raw `EXCEPTION_*` codes, and an uncaught
  fault becomes a generic SCIM 500 (see the exception/shutdown handler).
- **Audit logging** (opt-in via `setAuditLogDirectory()`): each successful mutating handler
  calls the private `writeAudit()`, which records actor/IP/action/target through `AuditLog`.
  The actor + method are captured in `enforceAuthentication` (`session`/`basic`/`bearer`);
  `deleteUser` reads the username before deleting so the entry is meaningful. Keep new
  mutations audited by adding a `writeAudit(...)` call on their success path.

### Authentication
- **`SessionAuth`** (singleton) manages PHP `$_SESSION` login state. Cookies are set
  `httponly` + `samesite=Strict`. It tracks login attempts (default max 10), throttles,
  periodically refreshes the cached user (`SESSION_REFRESH_TIME`/`refreshTime`, 60s),
  and supports **CSRF tokens** (`X-CSRF-Token`, compared with `hash_equals`). Key methods:
  `login()`, `logout()`, `isLoggedIn()`, `enforceLoggedIn()`, `isMemberOfGroup()`,
  `enforceMemberOfGroup()`, `getLoggedInUser()`. Login accepts either username or email
  (an `@` in the identifier routes to an email lookup).
- **`HeaderAuth::checkBasicAuthentication()`** is stateless — decodes an `Authorization:
  Basic` header and verifies the password. Requires the web server to pass the
  Authorization header through (see `demo/api/.htaccess`).
- **`BearerAuth`** is stateless OAuth Bearer-token auth for machine provisioning: configure
  tokens via `SCIM::setBearerTokens([...])` (opt-in, additive to session + Basic). A valid
  `Authorization: Bearer <token>` authorizes the request as the provisioning service with
  full admin rights and **no per-user lookup** — matching how Okta/Entra provision over
  SCIM. Tokens are stored only as SHA-256 hashes and compared with `hash_equals`; failed
  Bearer attempts are deliberately **not** throttled (the secret is high-entropy, and
  throttling would risk locking out a misconfigured-but-legitimate IdP).
- **Brute-force lockout** is enforced by `LoginThrottle`, shared across requests and keyed
  by identifier + `REMOTE_ADDR` (not the session), so it applies to both the session and
  HTTP Basic paths and cannot be reset by dropping the cookie. Both auth paths call
  `registerFailure`/`reset`; `SessionAuth::login` returns HTTP 429 when locked.
- **Admin** = membership in the `Administrators` group. `GroupProvider` auto-creates this
  group on first `getInstance()` and re-creates it after `deleteAll()`; `SCIM::deleteGroup`
  refuses to delete it (403). `User::isAdmin()` == `isMemberOf('Administrators')`.

### Groups & membership
- A `Group` stores member IDs as a plain array. `Group::addMember` only adds a member if
  the user **currently exists** (it calls `UserProvider::getInstance()->exists(...)`),
  and de-duplicates. Membership checks are case-insensitive via `Sanitizer`.
- Deleting a user via `UserProvider::delete` also strips them from every group (it reads
  all groups through `GroupProvider::getInstance()` and updates any that contained the id),
  so no stale membership references are left behind.

### Sanitization & validation
- Centralize input cleaning in `Sanitizer`: `sanitizeString` lowercases, trims, converts
  whitespace to `-`, strips anything outside `[a-z0-9_-]`. `REGEX_ID` and `REGEX_NAME`
  bound identifier formats. Prefer these helpers over ad-hoc regex.

## Coding style

Match the existing code — it is deliberately plain, framework-light PHP:
- `declare` no strict types; classes live under `namespace VoltCMS\UserAccess;`.
- 4-space indentation, K&R-ish braces, one class per file named after the class.
- Getters/setters for every entity field; validation belongs in setters.
- Providers are singletons with private `__construct`/`__clone` and a `__wakeup` that
  throws — preserve that pattern if you add another provider.
- Domain errors are thrown as `\Exception` with **stable string codes** (e.g.
  `EXCEPTION_USER_ALREADY_EXIST`, `EXCEPTION_DUPLICATE_EMAIL`, `EXCEPTION_ENTRY_NOT_EXIST`).
  Reuse existing codes; callers `switch` on `$e->getMessage()`.
- Large blocks of commented-out code (`RestApp.php`, `patch*`, the verbose `getUser`
  block) are historical scaffolding. **Do not treat them as active**; don't delete them
  wholesale either unless the task is a cleanup — they document intent.

## Testing conventions

- PHPUnit 10; tests live in `tests/` and are picked up by the `Unit Tests` suite in
  `phpunit.xml`. Bootstrap is `vendor/autoload.php`.
- `UserProviderTest` is an **integration test** that writes to `tests/data/*` (gitignored)
  through real FileDB and exercises providers + `SessionAuth` end to end. It calls
  `deleteAll()` at start and end to stay hermetic — keep that discipline if you extend it.
- `SCIMTest` unit-tests handlers with **mocked** `UserProviderInterface` /
  `GroupProviderInterface` and asserts on emitted output via `expectOutputRegex`. When
  adding SCIM behavior, mirror this: mock the providers, assert on the JSON body.
- Because handlers call `header()` and sometimes `exit()`, test them the way `SCIMTest`
  does (output-buffer assertions) rather than by invoking the router.

## Git & workflow expectations

- Data directories are gitignored: `/data/`, `/demo/data/`, `/tests/data/`, plus
  `/vendor/`, `/node_modules/`, `/.phpunit.cache`. Never commit generated data or deps.
- Keep changes minimal and consistent with the plain-PHP style above.
- Run `composer test` before finishing. CI (`.github/workflows/ci.yml`) runs the suite on
  PHP 8.4 plus a `php -l` lint matrix on 8.2/8.3/8.4, but tests are still your local safety
  net — run them.
- Do not create pull requests unless explicitly asked.

## Gotchas / things to know

- **Pagination**: `listUsers`/`listGroups` honor 1-based `startIndex` and `count`
  (via the shared `buildListResponse` helper); `totalResults` reflects the full filtered
  count before slicing. **Filtering**: a single `attribute eq "value"` expression is
  supported for **both** users and groups (shared `findByFilter` helper); anything else is
  rejected with 400. `ServiceProviderConfig` reports `filter.supported = true`
  (`maxResults = SCIM::MAX_FILTER_RESULTS`). Sort and bulk remain unsupported.
- **Location URLs** are derived from `$_SERVER` (`HTTP_HOST`, `SCRIPT_NAME`), so entity
  `toSCIM()` output depends on request context; expect empties in pure unit contexts.
- Passwords are hashed with `password_hash(PASSWORD_DEFAULT)`; `passwordHash` is stored in
  `getAttributes()` but stripped from `toSCIM()` output. Don't leak it in new responses.
  `User::validatePassword` enforces an 8–72 character policy in `hashPassword`/`setPassword`
  (72 = bcrypt's byte limit); `setPasswordHash` is exempt since it takes an existing hash.
- **`active` on write**: an omitted `active` is left unset by `parseUserPayload`, so create
  uses the entity default (`true`) and a `PUT` preserves the current value — only an
  explicit boolean/int flips it. Don't reintroduce a blanket `active=false` default.
- The demo seeds an `Administrator` user on first run with a hardcoded password — that is
  demo-only; never replicate hardcoded credentials in library code.
- `RestApp.php` is dead code (fully commented). The live router is `SCIM.php`.
- `Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP` now has a **distinct** value
  (`logged_in_not_member_of_group`) from `..._MEMBER_OF_GROUP`; earlier revisions shared
  one string, which broke the "not member of group" access state. `UtilsTest` guards this.
- Session cookies are set `httponly`, `samesite=Strict`, and `secure` over HTTPS;
  HTTPS is detected via `Utils::isHttps()`, which honors `X-Forwarded-Proto` /
  `X-Forwarded-SSL` so the flag and location URLs stay correct behind a TLS-terminating
  proxy. `SessionAuth::login()` calls `session_regenerate_id(true)` on success
  (session-fixation defense). `HeaderAuth::checkBasicAuthentication()` splits credentials
  on the first `:` only (passwords may contain colons) and performs a constant-time dummy
  verify for unknown users to avoid username enumeration via timing.

## Production readiness

This is a small, dependency-light library; several things are still needed before a
deployment can be considered production-grade. Tracked as a living checklist — check items
off (and add a one-line note) as they land.

### Deploying safely (data protection)

The flat-file store writes one JSON document per entity, and those documents contain the
**bcrypt `passwordHash` and PII**. `toSCIM()` strips `passwordHash` from API responses, but
the files on disk still hold it — so if the data directory is ever reachable over HTTP, the
hashes are downloadable.

- **The real fix: keep the data directory OUTSIDE the web root.** Point the provider
  `directory` at a path the web server does not serve (e.g. `/var/lib/voltcms/useraccess`).
- **Defense in depth (automatic):** `UserProvider` / `GroupProvider` call
  `Utils::protectDirectory()` on first `getInstance()`, dropping a deny-all `.htaccess`
  (`Require all denied`) and an empty `index.html` into the data dir. This protects Apache
  setups even if the dir lands in the web root; it is best-effort and silently skips when it
  cannot write.
- **nginx does not read `.htaccess`** — add the equivalent to your server config:
  ```nginx
  location ~ /data/ { deny all; return 404; }
  ```

### Checklist

Quick wins (done):

- [x] **Data-directory protection** — `Utils::protectDirectory()` writes deny-all
  `.htaccess` + `index.html`; out-of-web-root storage + nginx snippet documented above.
- [x] **Proxy-aware HTTPS detection** — `Utils::isHttps()` honors `X-Forwarded-Proto` /
  `X-Forwarded-SSL`; used for the secure cookie flag and all location URLs.
- [x] **Secure by default** — `SCIM` enforces admin authentication unless a caller
  explicitly opts out. The demo now runs **fully authenticated**: `demo/api/index.php`
  exposes `/auth/session`, `/auth/login`, `/auth/logout` and constructs `SCIM` with
  enforcement on; the UI gates behind a login form and drives the API with the session
  cookie.

Security / auth:

- [x] **Brute-force protection that can't be bypassed** — `LoginThrottle` persists failure
  counts to shared filesystem storage keyed by identifier + `REMOTE_ADDR`, so dropping the
  session cookie no longer resets the counter; wired into both `SessionAuth::login` (429
  when locked) and `HeaderAuth::checkBasicAuthentication`. Lockout = `maxLoginAttempts`
  failures within a 900s window, cleared on success. The `$_SESSION` counter is kept for
  backward-compatible login info but is no longer the security boundary.
- [x] **Bearer-token / OAuth auth** — `BearerAuth` validates `Authorization: Bearer <token>`
  against configured tokens (held as SHA-256 hashes, constant-time compared). Enable with
  `SCIM::setBearerTokens([...])`; a valid token authorizes as the provisioning service
  (admin) with no per-user lookup, alongside session + HTTP Basic. `ServiceProviderConfig`
  advertises `oauthbearertoken` when configured. The demo reads
  `USERACCESS_SCIM_BEARER_TOKEN`.
- [x] **Enforce HTTPS / add HSTS** — `SCIM::setHttpsPolicy()` (opt-in) refuses plaintext
  HTTP with a SCIM 403 before auth runs, and sends `Strict-Transport-Security` over HTTPS.
  Off by default (the local demo is http://localhost; TLS topology is deployment-specific)
  — production calls `$app->setHttpsPolicy(true)`. HTTPS is detected via `Utils::isHttps()`
  so it works behind a TLS-terminating proxy.
- [x] **Password policy** — `User::validatePassword` enforces a length of
  `PASSWORD_MIN_LENGTH`–`PASSWORD_MAX_LENGTH` (8–72; 72 is bcrypt's byte limit) in
  `hashPassword`/`setPassword`. SCIM maps `EXCEPTION_INVALID_PASSWORD` to a friendly 400 on
  create/replace/patch. `setPasswordHash` is exempt (it stores an existing hash).

Data integrity / scale:

- [x] **Concurrency control** — `Lock::exclusive()` is a process-wide, reentrant advisory
  write mutex (`flock(LOCK_EX)` on a per-install lock file) wrapping every provider
  mutation. The user-delete path now runs delete + group-strip under one lock so it is
  atomic against other writers. NOTE: this serializes flat-file writers safely but does not
  scale; a high-concurrency deployment should still move to a transactional store.
- [ ] **Backup / restore story** for the flat-file DB.

Error handling / robustness:

- [x] **Global exception handler** — `SCIM::runRouter()` installs an exception + shutdown
  handler that logs the fault and emits a clean SCIM 500 (only if headers aren't sent), and
  sets `display_errors=0` / `log_errors=1`. Unit tests call handlers directly so they are
  unaffected.
- [x] **Stop leaking internal exception codes** — `createUser` now wraps `fromSCIM` +
  `create`, maps known validation/domain codes to friendly 4xx messages, and returns a
  generic 500 (logging the real code) for anything else instead of echoing `EXCEPTION_*`.
- [x] **`active` footgun fixed** — `parseUserPayload` no longer injects `active=false` when
  the field is omitted; it only normalizes an explicit value. On create the `User` entity
  defaults to `active=true`; on a `PUT` that omits `active` the existing value is preserved
  (`fromSCIM` assigns `active` only when present), so a replace never silently deactivates.

Operational:

- [x] **CI** — `.github/workflows/ci.yml` runs `composer test` on PHP 8.4 and a `php -l`
  lint matrix on 8.2/8.3/8.4 on every push/PR. Still to add: PHPStan/Psalm and a
  coding-standard (PHP-CS-Fixer / PHPCS) check.
- [x] **Audit logging** of admin actions — `AuditLog` appends one JSON-Lines entry per
  successful create/update/patch/delete of a user or group, capturing actor (+ auth
  method), client IP, action, target id/name, and outcome. Enable with
  `SCIM::setAuditLogDirectory($dir)` (off by default; the demo logs to `../data/audit`).
  The log dir gets the same deny-all `.htaccess` and should live outside the web root.
- [ ] **Real README / deployment + hardening docs** — the current README is only an RFC
  excerpt.

SCIM completeness (interop):

- [ ] **Discovery + missing endpoints** — `/Me`, `/Schemas`, `/ResourceTypes`; Bulk; sort;
  richer filtering (only a single `attribute eq "value"` is supported).
- [ ] **`application/scim+json`** request/response content types (RFC 7644).

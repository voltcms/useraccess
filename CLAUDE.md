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
  Sanitizer.php            # String/array sanitization + validation regexes
  Utils.php                # Page-protection / content-visibility helpers for host apps
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

**Nothing is committed to `master` by CI here — there is no CI workflow in the repo.**
Always run `composer test` yourself before considering a change done.

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
- `enforceAuthentication` (default **false**) optionally gates the whole router: it
  requires a logged-in session user OR HTTP Basic credentials, and that the user
  `isAdmin()`. It is the **third constructor argument** —
  `new SCIM($userProvider, $groupProvider, true)` — defaulting to `false`, so the demo's
  `new SCIM($userProvider, $groupProvider, false)` keeps the router open.

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
- Run `composer test` before finishing. There is no lint/CI gate in-repo, so tests are
  the safety net.
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
- The demo seeds an `Administrator` user on first run with a hardcoded password — that is
  demo-only; never replicate hardcoded credentials in library code.
- `RestApp.php` is dead code (fully commented). The live router is `SCIM.php`.
- `Utils::ACCESS_STATUS_LOGGED_IN_NOT_MEMBER_OF_GROUP` now has a **distinct** value
  (`logged_in_not_member_of_group`) from `..._MEMBER_OF_GROUP`; earlier revisions shared
  one string, which broke the "not member of group" access state. `UtilsTest` guards this.
- Session cookies are set `httponly`, `samesite=Strict`, and `secure` under HTTPS;
  `SessionAuth::login()` calls `session_regenerate_id(true)` on success (session-fixation
  defense). `HeaderAuth::checkBasicAuthentication()` splits credentials on the first `:`
  only (passwords may contain colons) and performs a constant-time dummy verify for
  unknown users to avoid username enumeration via timing.

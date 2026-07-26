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
  CustomAttributesTest.php # Custom user attributes: entity rules + FileDB persistence
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
- **Custom user attributes**: beyond its fixed fields, `User` carries an open
  `customAttributes` map for host-defined data (`get/set/has/removeCustomAttribute`,
  `get/setCustomAttributes`, `clearCustomAttributes`). Names must match
  `Sanitizer::REGEX_ATTRIBUTE_NAME`, stay within `Sanitizer::ATTRIBUTE_NAME_MAX_LENGTH`,
  and must not collide with `User::RESERVED_ATTRIBUTE_NAMES` (otherwise a custom
  `passwordHash` would ride the attribute map into `setAttributes()`); values are a
  scalar, `null`, or a flat list of those. Lookups are case-insensitive. The map is
  persisted under `customAttributes` and exposed over SCIM under the extension URN
  `User::CUSTOM_SCHEMA` — see "Custom attributes over SCIM" below.
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
  `/scim/users`, `/scim/users/{uuid}`, `/scim/groups`, `/scim/groups/{uuid}`, the discovery
  endpoints `/scim/ServiceProviderConfig[s]`, `/scim/ResourceTypes[/{id}]`,
  `/scim/Schemas[/{urn}]`, and `/scim/Me` to handler methods. All responses use the
  `application/scim+json` content type via `emitScim()`.
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
- **Custom attributes over SCIM**: host-defined user attributes travel in the extension
  object `urn:ietf:params:scim:schemas:extension:voltcms:2.0:User` (`User::CUSTOM_SCHEMA`),
  accepted on create/PUT whether or not the client also declares the URN in `schemas`, and
  echoed back (with the URN appended to `schemas`) only when the user actually has any.
  PATCH understands `<urn>:<name>` and the `customAttributes.<name>` alias for a single
  attribute, and the bare root path for the whole set — `add` merges, `replace` swaps,
  `remove` clears. `showResourceTypes` advertises it via `schemaExtensions` and
  `showSchemas` serves the (deliberately attribute-less, because deployment-defined)
  extension schema. Filtering on custom attributes is not supported.
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
  whitespace to `-`, strips anything outside `[a-z0-9_-]`. `REGEX_ID`, `REGEX_NAME` and
  `REGEX_ATTRIBUTE_NAME` (paired with `ATTRIBUTE_NAME_MAX_LENGTH`, checked separately so
  the length bound is not duplicated inside the pattern) bound identifier formats. Prefer
  these helpers over ad-hoc regex.

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

The rule-by-rule baseline (with the counts behind each call) is in **Coding standards**
below; that section wins where the two overlap.

## Coding standards

A survey-derived baseline for this repo. Every rule below was checked against the actual
sources, and each cites what the codebase does today.

**How to read this.** Each rule states the convention that **dominates by volume** and the
one that is **better on merit**. Where they agree, the rule is just "keep doing this."
Where they differ the rule is marked **⚠ split** — in those cases *write new code the
better way and leave existing code alone*; none of these are worth a reformatting sweep,
and `phpcs.xml.dist` is deliberately narrow for exactly that reason. Counts exclude
`src/RestApp.php` (dead, fully commented, PHPStan-excluded) unless stated.

### PHP — syntax and formatting

**Lowercase `const`.** Dominant (20 of 24) and better. `CONST` survives only in `User.php`.

```php
const SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';   // good
CONST SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';   // bad — User.php:11
```

**Declare constant visibility.** ⚠ split: bare `const` dominates (21 of 24); explicit
visibility (`Sanitizer`, `HeaderAuth`) is better — it says whether the constant is API or
an implementation detail. New constants get a modifier.

```php
private const DUMMY_PASSWORD_HASH = '$2y$12$...';   // good — HeaderAuth.php:13
const MAX_FILTER_RESULTS = 200;                     // bad  — SCIM.php:11 (is this API?)
```

**No leading backslash in `use` statements.** ⚠ split: 40 of 48 imports carry a leading
`\`; the no-backslash form is better (a `use` path is always absolute, so the `\` is
noise) and is what the newest files already do — `SCIMTest.php` (all 7) and
`demo/api/index.php:5`.

```php
use VoltCMS\UserAccess\User;    // good
use \VoltCMS\UserAccess\User;   // bad
```

**Don't fully-qualify global function calls.** Dominant — two exceptions in the whole tree —
and better; the `\` prefix reads as a namespace hint that means nothing here.

```php
return password_hash($password, PASSWORD_DEFAULT);    // good
return \password_hash($password, PASSWORD_DEFAULT);   // bad — User.php:145, :162
```

**Short array syntax `[]`.** ⚠ split: `array()` has 100 uses in `src/` but **86 of them are
inside `SCIM.php`** — every other file, and the whole test suite, is already `[]`. `[]` is
better and is the majority once `SCIM.php` is set aside. New code uses `[]`, including new
handlers in `SCIM.php`.

```php
$payload['patch'] = ['supported' => true];             // good
$payload['patch'] = array("supported" => true);        // bad — SCIM.php:810
```

**Strict comparison `===` / `!==`.** Narrowly dominant (50 `===` vs 31 `==`) and better.
Loose comparison is actively wrong in places: `$payload[$schema] == ""` (SCIM.php:447)
is true for `0`, `null`, and `[]`.

```php
if ($attribute === 'id') { ... }   // good
if ($attribute == 'id') { ... }    // bad — UserProvider.php:42
```

**`elseif`, not `else if`.** Dominant (14 vs 4) and better.

```php
} elseif ($groupProvider->exists('id', $group)) {     // good — SCIM.php uses this
} else if ($groupProvider->exists('id', $group)) {    // bad  — User.php:171
```

**Opening brace on its own line for function declarations.** Dominant (all but two) and
better here because it is what 167 of 169 methods do.

```php
public function fromSCIM(array $attributes): void
{                                                  // good
public function fromSCIM(array $attributes) {      // bad — User.php:308, GroupProvider.php:134
```

**Single-quoted strings unless interpolating.** Dominant (1058 vs 299) and better. The
biggest offender is header emission — `header("...")` 21× vs `header('...')` 6×.

```php
header('Content-Type: application/scim+json', true, 200);   // good
header("Content-Type: application/scim+json", true, 200);   // bad — SCIM.php:228 et al
$this->throwError(404, 'Not Found');                        // good
$this->throwError(404, "Not Found");                        // bad — SCIM.php:86
```

**No blank line after a class's opening brace.** ⚠ split: 11 of 15 classes have one; the
four newest (`AuditLog`, `BearerAuth`, `Lock`, `LoginThrottle`) do not, and that is better
(PSR-12 forbids it). New classes: no blank line.

```php
class BearerAuth
{
    private $tokenHashes = [];      // good — BearerAuth.php:22
}

class Group
{

    const RESOURCE_TYPE = 'Group';  // bad — Group.php:9-10
}
```

**Empty singleton bodies stay as `{}` on the following line.** Uniform across all three
singletons — keep it if you add a fourth.

```php
private function __construct()
{}                                  // good — UserProvider.php:29-30
```

### PHP — types and signatures

**Declare return types on every new method.** Narrowly dominant (97 of 169 typed) and
better. The untyped 72 are concentrated in the entity setters and every public `SCIM`
handler; add `: void` to the former and a real type to the latter as you touch them.

```php
public function setDisplayName(string $displayName): void   // good
public function setDisplayName(string $displayName)         // bad — User.php:73
```

**Declare parameter types.** Split by layer, not by count: entities and providers are fully
typed, `SCIM` handlers and `Utils` are almost entirely untyped. Typed is better. Use
`mixed` for genuinely polymorphic SCIM values rather than omitting the type.

```php
private function extractMemberIds(mixed $value): array   // good
private function extractMemberIds($value): array         // bad — SCIM.php:1213
public function listUsers(array $options): void          // good
public function listUsers($options)                      // bad — SCIM.php:326
```

**Declare property types.** ⚠ split, and the starkest one: **1 of 51** properties is typed
(`Lock::$depth`). Typed is better, and `SessionAuth.php:22-23` carries commented-out typed
declarations showing the intent. Type new properties; `SCIM`'s 13 untyped fields are the
best place to start when one is touched anyway.

```php
private static int $depth = 0;   // good — Lock.php:24
private ?User $loggedInUser = null;  // good
private $loggedInUser;               // bad — SCIM.php:19
```

**Scalar type names are lowercase.** Two stragglers, both in the provider interfaces. PHP
accepts `String` (type names are case-insensitive) so this is silent, not broken.

```php
public function read(string $attribute, string $value): User;   // good
public function read(String $attribute, string $value): User;   // bad — both *ProviderInterface.php:14
```

**No `declare(strict_types=1)`.** Uniform (zero files) — and adding it to one file only
would change coercion behavior asymmetrically across the call graph. Leave it off unless
the whole tree flips at once.

### PHP — error handling

**Two layers, two mechanisms — don't mix them.** Domain code (entities, providers) throws
`\Exception` with a stable `EXCEPTION_*` string as the *message*; HTTP code (`SCIM`)
converts to a SCIM error body via `throwError()`. A provider must never emit HTTP; a
handler must never let an `EXCEPTION_*` code reach the client.

```php
throw new Exception('EXCEPTION_DUPLICATE_EMAIL');            // good — in a provider
exit($this->throwError(400, $e->getMessage()));              // bad  — leaks the code
exit($this->throwError(400, $this->messageForException($e->getMessage())));  // good
```

**Call `throwError()` bare — it already exits.** ⚠ split: 78 of 90 call sites wrap it as
`exit($this->throwError(...))`, but `throwError()` ends in `exit(json_encode(...))`, so the
wrapper is unreachable and misleads readers into thinking it returns a value. Bare is
better and is what the 12 newer call sites do.

```php
$this->throwError(404, 'Selected user does not exist.');          // good — SCIM.php:235
exit($this->throwError(404, 'Selected user does not exist.'));    // bad  — SCIM.php:374
```

**Every new `EXCEPTION_*` code needs a `messageForException()` arm.** Otherwise it falls
through to the generic "The request could not be completed." and the client learns nothing.
Add a `statusForException()` arm too when the code isn't a 400.

**Wrap entity + provider calls in a handler's try/catch.** Inconsistent today: `createUser`,
`putUser`, `patchUser`, `patchGroup` map domain exceptions to 4xx; `createGroup` (SCIM.php:641)
and `putGroup` (SCIM.php:764) don't, so a duplicate display name there escapes to the global
handler as a **500 instead of a 409**. Mapping is both the majority (4 of 6) and correct.

```php
try {                                            // good — createUser/putUser/patch*
    $group->fromSCIM($attributes);
    $group = $this->groupProvider->create($group);
} catch (Exception $e) {
    error_log('createGroup failed: ' . $e->getMessage());
    exit($this->throwError($this->statusForException($e->getMessage()),
        $this->messageForException($e->getMessage())));
}

$group->fromSCIM($attributes);                   // bad — SCIM.php:641-642, unguarded
$group = $this->groupProvider->create($group);
```

**Emit SCIM bodies through `emitScim()`.** ⚠ split: 11 inline `header(...) + echo
preg_replace(...)` sites vs 6 `emitScim()` calls. The helper is better — it is the single
place the `application/scim+json` type and the control-character strip are guaranteed to
travel together.

```php
$this->emitScim($payload, 201);                             // good — SCIM.php:966
header("Content-Type: application/scim+json", true, 201);   // bad  — SCIM.php:228-229
echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
```

### PHP — naming

**camelCase for variables and parameters.** Dominant (38 snake_case occurrences, 11 distinct
names, all confined to `Utils.php` and `SessionAuth.php`) and better. **Do not rename the
existing ones without checking callers** — they are public parameter names, so a rename
breaks any host that uses named arguments (see open question 2).

```php
public static function protectPage($sessionAuth, $userStatus, $loggedInMemberOfGroup, ...)    // good
public static function protectPage($sessionAuth, $user_status, $logged_in_member_of_group, ...) // bad — Utils.php:39
```

**Method names are camelCase, and call them with the casing they were declared.** PHP method
names are case-insensitive so the mismatch is silent, which is exactly why it survives.

```php
$sessionAuth->logout();   // good — matches SessionAuth.php:251
$sessionAuth->logOut();   // bad  — UserProviderTest.php:168, :181
```

**Leading-underscore fields mean "storage-managed metadata", nothing else.** `$_id`,
`$_created`, `$_modified` mirror FileDB's document keys. Don't use `_` as a "private"
marker on ordinary fields; `private` already says that.

```php
private $_modified = '';    // good — FileDB metadata (User.php:19)
private $_userName = '';    // bad  — ordinary field, no underscore
```

**Return booleans directly.** Minor but repeated (`SessionAuth.php:280-284`,
`Utils.php:109-113`).

```php
return $loggedInUser && $loggedInUser->isMemberOf($group);   // good
if (...) { return true; } else { return false; }             // bad
```

### PHP — comments and docblocks

**Line comments (`//`) above the declaration for rationale.** Dominant and uniform: the
`src/` tree contains **zero** `/** */` docblocks. The existing comments are unusually good —
they explain *why* (`BearerAuth`'s throttling rationale, `Lock`'s reentrancy note,
`Utils::isHttps`'s proxy caveat). Keep writing those.

**⚠ split: add `/** */` on public API where types are ambiguous.** Volume says "never use
docblocks"; merit says a Packagist-published library should annotate `array` shapes so
PHPStan can be raised past level 2 and IDEs can autocomplete. The compromise: keep `//` for
rationale, add a docblock **only** when a signature's `array` hides a shape.

```php
/** @param array<int, array{value: string}>|string $value */   // good — worth stating
private function extractMemberIds($value): array

/** Sets the display name. */                                  // bad — restates the signature
public function setDisplayName(string $displayName): void
```

**Never add new commented-out code.** The existing blocks (`RestApp.php`, the ~80 dead lines
in `getUser`, ~40 in `getGroup`) are grandfathered scaffolding. Git history is the archive.

### Tests

**One `testXxx` method per behavior, named after the behavior.** Dominant (38 named methods
across 5 files) and better. Two files use a catch-all `test()` — `UserTest.php:9` and
`UserProviderTest.php:13`, the latter ~175 lines covering providers, groups, passwords, and
`SessionAuth` in one method, so a single failure hides everything after it.

```php
public function testDeletingUserRemovesGroupMembership()   // good — MembershipTest.php:12
public function test()                                     // bad  — UserProviderTest.php:13
```

**`assertSame` for scalars, `assertEquals` only when loose comparison is the point.** ⚠ split:
`assertEquals` dominates (29 vs 13); `assertSame` is better because `assertEquals` will not
catch a `'1'` where `1` is expected.

```php
$this->assertSame('userid1', $user->getUserName());     // good
$this->assertEquals('userid1', $user->getUserName());   // acceptable but weaker
```

**Expected value first.** PHPUnit's signature is `(expected, actual)`; 11 of the 25 live
`assertEquals` calls in `UserProviderTest` are reversed, which inverts every failure message.

```php
$this->assertSame(3, $_SESSION[SessionAuth::UA_ATTEMPTS]);       // good
$this->assertEquals($_SESSION[SessionAuth::UA_ATTEMPTS], 3);     // bad — UserProviderTest.php:154
```

**Pick the test kind by what you're testing.** Both styles are correct and intentional:
persistence/membership semantics → integration test against real FileDB in `tests/data/*`,
opening *and* closing with `deleteAll()` (`UserProviderTest`, `MembershipTest`); SCIM handler
behavior → `createMock`/`createStub` providers plus output assertions (`SCIMTest`,
`HeaderAuthTest`, `BearerAuthTest`). Never reach for a real provider to test a handler.

**Restore global state in `tearDown()`.** Handlers and auth read `$_SERVER`/`$_SESSION` and
`SCIM`'s constructor initializes the `SessionAuth` singleton; without cleanup the mocks leak
into later tests. `SCIMTest.php:25-33` and `BearerAuthTest.php:9-12` show both shapes.

**camelCase locals in tests too.** `$user_test1` / `$user_test2` (`UserProviderTest`) are the
only snake_case locals in the suite.

### Demo JavaScript (`demo/ui/js/useraccess.js`)

**`demo/ui/js/color-modes.js` is vendored** from the Bootstrap docs (see its copyright
header) — 2-space indent, no semicolons, single quotes. Don't restyle it and don't read
style cues from it. Everything below applies to `useraccess.js`, which is 4-space, double-
quoted, semicolon-terminated.

**Real class methods, not fields assigned function expressions.** ⚠ split: 17 fields vs 1
real method (`init()`). Methods are better — they live on the prototype, and the current
form only works because every call goes through `this.x()`.

```js
async loadUsers() { ... }                    // good — matches init()
loadUsers = async function () { ... }        // bad — 17 sites
```

**`async`/`await` with `try`/`catch`, not `.then()` chains.** ⚠ split: 25 `.then()` vs 4
`await`. Nearly every method is declared `async` yet never awaits and returns nothing, so
callers cannot await them and failures vanish into `.catch(console.error)`. `login()`
(line 62) already shows the better shape — copy it.

```js
async loadUsers() {                                       // good
    try {
        const response = await fetch("../api/scim/users");
        if (response.status === 401) { this.showLogin(); return; }
        const data = await response.json();
        ...
    } catch (error) {
        console.error("Error loading users:", error);
    }
}

loadUsers = async function () {                           // bad — lines 181-276
    fetch("../api/scim/users").then(r => r.json()).then(data => { ... }).catch(...);
}
```

**`const`/`let`, never `var` — and never redeclare a name with a new type.** Dominant
(24 `const`, 0 `let`, 8 `var`) and better. All 8 `var`s are the same bug shape: `var data =
{...}` followed by `var data = JSON.stringify(data)` in the same scope, silently turning an
object into a string.

```js
const payload = { schemas: [...], userName: formData.get("userName") };   // good
const body = JSON.stringify(payload);

var data = { ... };                        // bad — lines 444/465, 491/516, 567/582, 608/623
var data = JSON.stringify(data);
```

**`===` / `!==`.** ⚠ split: 12 loose vs 2 strict; strict is better. `response.status == 204`
and `data.Resources.length == 0` are the common cases.

```js
if (response.status === 204) { ... }   // good
if (response.status == 204) { ... }    // bad — lines 550, 657
```

**No `? true : false`.** Four sites (lines 398, 432, 452, 498).

```js
active: formData.get("active") === "on",                    // good
"active": formData.get("active") == "on" ? true : false,    // bad
```

**Use the cached element fields the class already defines.** `loadUser()` (lines 158-179)
calls `document.getElementById("updateUserForm")` six times although `this.updateUserForm`
is a field.

```js
this.updateUserForm.querySelector("[name=\"id\"]").value = data.id;                    // good
document.getElementById("updateUserForm").querySelector("[name=\"id\"]").value = ...;  // bad
```

### Files, layout and hygiene

**One class per file, filename identical to the class, PSR-4 under `src/`.** Uniform — no
exceptions. Test classes are `tests/<Class>Test.php` in the **global** namespace (also
uniform, though see open question 8).

**Files end with exactly one newline; no trailing whitespace; LF; 4-space indent; no tabs.**
This is what `phpcs.xml.dist` enforces — but **only over `src/`**, which is why the three
violations all sit outside it: `tests/SCIMTest.php` and both JS files lack a final newline,
and `tests/UserProviderTest.php:27` has trailing whitespace.

**Before finishing, run the checks that exist.** `composer test`, `composer phpstan`
(level 2 over `src/`), `composer phpcs` — all three run in CI on every push.

### Open questions

Genuinely unresolved from reading the repo alone; these need a maintainer's call rather than
a guess.

1. **How far should the phpcs ruleset go?** `phpcs.xml.dist` says it is narrow on purpose,
   "without imposing a wholesale reformat." Several rules above (`[]` over `array()`, no
   leading `\` in imports, no blank line after the class brace) are mechanically checkable
   and auto-fixable by `phpcbf` — but turning them on means one large diff. Adopt them as
   enforced sniffs, or leave them as review-time guidance?
2. **Are the snake_case public parameter names part of a host contract?** `Utils::protectPage`
   and `Utils::isContentVisible` are page-protection helpers for VoltCMS. If the host calls
   them with named arguments (`protectPage(user_status: ...)`), renaming is a breaking change.
   I could not determine this from this repository.
3. **Is the duplication of `setHeader()` deliberate?** `Utils::setHeader()` (public, static)
   and `SessionAuth::setHeader()` (private, instance) have identical bodies. Keeping
   `SessionAuth` self-contained is a defensible reason; if it isn't the reason, one should go.
4. **Is `$_id` / `$_created` / `$_modified` an on-disk contract?** They look like FileDB's
   metadata keys, which would mean the PHP property names are free to change but the array
   keys in `getAttributes()`/`setAttributes()` are not. I could not verify FileDB's contract
   (dependencies are not installable in this environment).
5. **Which PHP version governs style choices?** `composer.json` requires `>=8.2` and the lint
   matrix covers 8.2/8.3/8.4, so 8.2 is the floor — but is constructor property promotion /
   `readonly` welcome at all, given the codebase's deliberate explicit-getter/setter style?
   The two conventions pull in opposite directions for new entity classes.
6. **Does `demo/` count as shipped code?** phpcs and PHPStan skip it; `php -l` covers it. It
   uses `array()` throughout and seeds a hardcoded password. Exempt example code, or held to
   the same bar minus the credential?
7. **Is PHPStan meant to rise above level 2?** Several rules above (property types, parameter
   types, array-shape docblocks) are worth much more if the level is going up and mostly
   cosmetic if it is not.
8. **Should tests be namespaced?** They are global-namespace classes with no `autoload-dev`
   entry, found by directory. Uniform, and it works — deliberate simplicity, or drift?

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
- [ ] **Backup / restore story** for the flat-file DB. _(Deferred to a follow-up PR.)_

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

- [x] **CI** — `.github/workflows/ci.yml` runs `composer test` on PHP 8.4, a `php -l`
  lint matrix on 8.2/8.3/8.4, **PHPStan** (`composer phpstan`, `phpstan.neon.dist`,
  level 2 over `src/`), and a **PHP_CodeSniffer** coding-standard check (`composer phpcs`,
  `phpcs.xml.dist`) on every push/PR. The PHPStan level is deliberately conservative and
  can be raised as type hints are added.
- [x] **Audit logging** of admin actions — `AuditLog` appends one JSON-Lines entry per
  successful create/update/patch/delete of a user or group, capturing actor (+ auth
  method), client IP, action, target id/name, and outcome. Enable with
  `SCIM::setAuditLogDirectory($dir)` (off by default; the demo logs to `../data/audit`).
  The log dir gets the same deny-all `.htaccess` and should live outside the web root.
- [x] **Real README / deployment + hardening docs** — `README.md` documents features,
  install, quick start, the SCIM API + all three auth modes, security/hardening,
  configuration, the demo, testing/CI, a production deployment checklist, and a
  self-contained "For AI agents" integration recipe.

SCIM completeness (interop):

- [x] **Discovery + `/Me`** — `/scim/ResourceTypes` (+ `/{id}`), `/scim/Schemas` (+ `/{urn}`),
  `/scim/ServiceProviderConfig` (singular alias of the legacy plural), and `/scim/Me`
  (returns the session/Basic user; 404 for a Bearer service token). Handlers:
  `showResourceTypes` / `showSchemas` / `showMe`.
- [x] **`application/scim+json`** — all SCIM responses (and errors) now send the RFC 7644
  content type via the shared `emitScim()` helper.
- [ ] **Bulk, sort, richer filtering** — still unsupported and advertised as such in
  `ServiceProviderConfig`; filtering handles a single `attribute eq "value"` expression.

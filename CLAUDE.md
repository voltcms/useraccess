# CLAUDE.md

**VoltCMS UserAccess** — a dependency-light PHP 8 library for user/group management over a flat-file JSON store (`voltcms/filedb`),
exposed as a **SCIM 2.0** REST API (RFC 7643/7644) with session, HTTP-Basic and Bearer auth. Composer package, PSR-4
`VoltCMS\UserAccess\` → `src/`; embedded in a host app, not run standalone. `src/` holds the entities, the providers, `SCIM` (router
+ handlers, the main entry point), the three auth classes, `LoginThrottle`, `Lock`, `AuditLog`, `Sanitizer`, `Utils` and the dead
`RestApp`; `demo/api` wires them together, `demo/ui` is a Bootstrap 5 admin UI. Open work: **TODO.md**.

## Build & test

PHP ^8.2 (CI tests on 8.4; PHPUnit 13 needs >=8.4.1), Composer 2. Run all three before finishing; CI adds `php -l` on 8.2/8.3/8.4.

```bash
composer install && composer test   # phpunit
composer phpstan                    # level 2 over src/, excludes the dead RestApp.php
composer phpcs                      # coding standard (composer phpcbf autofixes)
```

## Architecture

- **Entities vs providers.** Entities are plain objects with `get*/set*`, validation *in the setters*, and SCIM (de)serialization
  (`toSCIM`/`fromSCIM`/`get|setAttributes`). Providers are singletons over a `FileDB` rooted at `$config['directory']`, exposing
  `exists/read/create/readAll/find/update/delete/deleteAll`. Depend on the interface, not the concrete class.
- **Persistence.** One JSON document per entity; UUID ids (routes match a strict UUID regex), lowercased and trimmed before lookup.
  `_id`/`_created`/`_modified` are FileDB metadata — the *array keys* in `get|setAttributes()` are the on-disk contract, so don't
  rename them.
- **Writes are serialized.** Every mutating provider method runs inside `Lock::exclusive()`, a reentrant `flock` mutex (FileDB has
  none); reads are unlocked. Keep new mutations inside it and rely on reentrancy for cross-provider sequences —
  `UserProvider::delete` also strips the user from every group.
- **Custom user attributes.** An open `customAttributes` map beside the fixed fields; names must match
  `Sanitizer::REGEX_ATTRIBUTE_NAME`, fit `ATTRIBUTE_NAME_MAX_LENGTH` and avoid `User::RESERVED_ATTRIBUTE_NAMES` (else a custom
  `passwordHash` rides into `setAttributes()`). Values are a scalar, `null` or a flat list, looked up case-insensitively, carried
  over SCIM in the `User::CUSTOM_SCHEMA` extension object, and not filterable.
- **SCIM layer.** `bramus/router` maps the user, group, discovery and `/scim/Me` routes to handlers; `patchUser`/`patchGroup`
  implement PatchOp, validation lives in `parseUserPayload`/`parseGroupPayload`. Pagination and a single `attribute eq "value"`
  filter work; sort and bulk do not.
- **Auth.** `enforceAuthentication` is the third constructor arg, **default true** — needs an admin session user, admin Basic
  credentials, or a Bearer token (`setBearerTokens()`, SHA-256 hashed, `hash_equals`, deliberately unthrottled). Admin = membership
  in `Administrators`, auto-created by `GroupProvider` and undeletable via SCIM (403). Lockout is `LoginThrottle`, keyed by
  identifier + `REMOTE_ADDR` rather than the session, so it covers both paths. HTTPS enforcement (`setHttpsPolicy()`) and audit
  logging (`setAuditLogDirectory()`) are opt-in — add a `writeAudit()` call to any new mutation.

## Coding standards

Plain, framework-light PHP targeting the 8.2 floor. No `declare(strict_types=1)` anywhere — that change must be tree-wide or not at
all. Entities keep explicit getters/setters; constructor property promotion and `readonly` are not used for them.

**Syntax, naming, types.** Declare visibility on every constant. No leading `\` in `use` statements — `src/` is clean apart from the
dead `RestApp`, but `tests/` (24) and `demo/` (5) still carry them. Don't fully-qualify global function calls. Strict `===`/`!==`.
`elseif`, not `else if`. Opening brace on its own line for functions; empty singleton bodies stay `{}` on the following line. No
blank line after a class's opening brace. Single quotes unless interpolating or the string embeds a `'`. camelCase for variables and
parameters; a leading underscore means "FileDB metadata" (`$_id`/`$_created`/`$_modified`) and nothing else. Return booleans
directly. Declare return, parameter and property types on everything new — the tree is almost fully typed, the only remnants being
the `Utils`/`SessionAuth::getInstance` params, `$_created`/`$_modified` and `Lock::$handle` (a resource, which has no type). Use
`mixed` for polymorphic SCIM values, and lowercase type names.

**Errors — two layers, don't mix them.** Domain code throws `\Exception` with a stable `EXCEPTION_*` string as the message; `SCIM`
converts it to a SCIM error body. A provider never emits HTTP; a handler never lets an `EXCEPTION_*` code reach the client. Call
`throwError()` bare — it already `exit()`s. Every new `EXCEPTION_*` needs a `messageForException()` arm (plus `statusForException()`
when it isn't a 400). Wrap entity + provider calls in a handler try/catch, and check a target exists before `read()`ing it — every
create/put/patch handler now does both, so no domain fault escapes as a 500. Emit all SCIM bodies through `emitScim()`.

**Comments.** `//` above the declaration, explaining *why*. The only docblocks in `src/` are four array-shape annotations — an
ambiguous `array` shape is the one case worth one. Never add new commented-out code; the existing blocks (`RestApp`, the dead bodies
in `getUser`/`getGroup`) are grandfathered scaffolding — don't treat them as active, don't delete them wholesale outside a cleanup
task. `RestApp`'s class shell, properties and constructor signature *are* live code (only the bodies are commented), so it lints.

**Tests.** One `testXxx` method per behavior, named for the behavior. `assertSame` for scalars, expected value first. Pick the kind
by target: persistence/membership → integration test against real FileDB in `tests/data/*`, opening *and* closing with
`deleteAll()`; SCIM handler behavior → mocked providers plus output assertions, never a real provider. Restore
`$_SERVER`/`$_SESSION` in `tearDown()`. Tests stay in the global namespace.

**Demo JS** (`demo/ui/js/useraccess.js`; `color-modes.js` is vendored from the Bootstrap docs — don't restyle it or take style cues
from it). Real class methods, not fields assigned function expressions. `async`/`await` with `try`/`catch`, not `.then()` chains —
`login()` shows the shape. `const`/`let`, never `var`, and never redeclare a name with a new type. `===`/`!==`. No `? true : false`.
Use the cached element fields the class already defines. The file predates the standards and breaks every one of those lines:
rewrite target, not a model.

**Layout, and what tooling enforces.** One class per file, filename identical to the class, PSR-4 under `src/`; tests are
`tests/<Class>Test.php`. `demo/` is example code — `php -l` only, and its hardcoded seed password must never be copied into library
code. `phpcs.xml.dist` covers `src/` **and** `tests/`: no tabs, LF endings, no BOM, no trailing whitespace on non-blank lines, file
ends in a newline, long-form open tags, lowercase keywords, lowercase `true`/`false`/`null`, and short array syntax — so none of
those are restated above. It stays narrow on purpose: the no-leading-`\` import rule and the class-brace rule are also
`phpcbf`-fixable, but enforcing them would reformat `tests/` wholesale, so they remain review-time guidance. Gaps: **4-space indent
is convention, not enforced** (only tabs are rejected); **`demo/` is outside phpcs and phpstan**; and **there is no ESLint or
Prettier**, so nothing checks `demo/ui/js/` — which is why both JS files lack a final newline.

## Gotchas

- `passwordHash` is stored by `getAttributes()` but stripped from `toSCIM()` — don't leak it in new responses. Passwords are 8–72
  chars (`User::validatePassword`; 72 is bcrypt's byte limit); `setPasswordHash` is exempt.
- **`active` on write:** an omitted `active` stays unset, so create uses the entity default (`true`) and a `PUT` preserves the
  current value. Don't reintroduce a blanket `active=false`.
- Location URLs derive from `$_SERVER`, so `toSCIM()` output is request-dependent — expect empties in unit contexts.
  `Utils::isHttps()` honors `X-Forwarded-Proto`/`X-Forwarded-SSL`, keeping those URLs and the secure cookie flag right behind a
  TLS-terminating proxy.
- **Deployment:** keep the data directory outside the web root. Providers call `Utils::protectDirectory()` (deny-all `.htaccess` +
  empty `index.html`) as best-effort defense in depth; nginx ignores it, so add `location ~ /data/ { deny all; return 404; }`. Data
  dirs are gitignored — never commit generated data or `vendor/`.

# TODO

Open work for `voltcms/useraccess`. Conventions and architecture live in **CLAUDE.md**; this file tracks only
what is still outstanding. Everything on the former production-readiness checklist that was marked done has
been dropped — git history is the record.

## Correctness

- [x] **`createGroup` / `putGroup` map domain exceptions.** Both now wrap `fromSCIM()` + the provider call in
  the same try/catch `createUser` / `putUser` / `patch*` use, so a lost display-name race is a 409 and an
  empty member id a 400 rather than a 500. `putGroup` also checks the id exists before `read()`ing it, which
  turns an unknown group into a 404 instead of a 500.
- [x] **`Utils::getBoolean()` accepts the usual truthy spellings.** It now takes `true`/`yes`/`on`/`1` in any
  casing (trimmed), plus real booleans and `int` 1, instead of only the literal string `'True'` under `==`.
- [ ] **`Utils::setHeader()` is dead code** duplicating `SessionAuth`'s private copy (no callers anywhere in
  `src/`, `tests/` or `demo/`). It is published API, so removal is a BC break; decide whether to deprecate it
  for the next major or keep it.
- [ ] **SCIM error paths are untestable.** `throwError()` ends in `exit()`, so no test can assert a 4xx body —
  which is why the suite has zero error-path tests and the two fixes above are covered only by their success
  paths. Making it throw a dedicated exception that `runRouter()` converts would open all of them up.

## Data integrity

- [ ] **Backup / restore story for the flat-file store.** No documented or scripted path today; a deployment
  has to roll its own. (Was deferred from the production-readiness pass.)
- [ ] **`Lock::exclusive()` serializes writers but does not scale.** Fine for the flat-file store; a
  high-concurrency deployment should move to a transactional backend. Documented, not solved.

## SCIM completeness

- [ ] **Bulk, sort and richer filtering.** Still unsupported and advertised as such in
  `ServiceProviderConfig`; filtering handles a single `attribute eq "value"` expression only. Filtering on
  custom attributes is also unsupported.

## Tooling

- [ ] **No JS linter.** There is no ESLint or Prettier config, so nothing checks `demo/ui/js/`. Both JS files
  lack a final newline as a result. Adding one means a dev dependency and a CI job; decide whether demo-only
  JS earns that.
- [ ] **Raise PHPStan above level 2.** The conservative level was chosen when `src/` was largely untyped.
  Return, parameter and property types are now nearly complete, so level 4–5 is plausible; try it and see
  what falls out. `RestApp.php` stays excluded.
- [ ] **phpcs does not cover `demo/`** (nor does PHPStan). `php -l` is the only gate there. Related open call:
  whether `demo/` should be held to the same standard minus the hardcoded seed password.
- [ ] **4-space indentation is not enforced**, only the absence of tabs. `Generic.WhiteSpace.ScopeIndent`
  would cover it but has not been verified clean against the tree.

## Cleanups (low priority, no behavior change)

- [ ] **`tests/UserProviderTest.php` and `tests/UserTest.php` use a catch-all `test()` method.** The former is
  ~175 lines covering providers, groups, passwords and `SessionAuth`, so one failure hides everything after
  it. Split into per-behavior `testXxx` methods like the newer test files.
- [ ] **`assertEquals` → `assertSame`, and reversed argument order** in `UserProviderTest` (PHPUnit's
  signature is `(expected, actual)`; several calls are inverted, which inverts the failure messages). Also
  the `$user_test1` / `$user_test2` snake_case locals and the `logOut()` call spelled against the declared
  `logout()`.
- [ ] **`demo/ui/js/useraccess.js` predates the JS standards** and breaks all of them: 17 fields assigned
  function expressions instead of methods, 25 `.then()` chains, 8 `var`s (four of them the `var data = {...}`
  / `var data = JSON.stringify(data)` shape that silently retypes the binding), 12 loose `==`, four
  `? true : false`, and repeated `getElementById` where a cached field exists. A rewrite, not a patch.
  `color-modes.js` is vendored from the Bootstrap docs — leave it alone.
- [ ] **29 `use` statements still carry a leading `\`** — 24 in `tests/`, 5 in `demo/api/index.php`, plus one
  in the dead `RestApp.php`. `phpcbf`-fixable, but it reformats `tests/` wholesale, so it stays review-time
  guidance rather than a sniff for now. (`array()` is done: zero live calls remain in `src/` or `tests/`, and
  `Generic.Arrays.DisallowLongArraySyntax` now enforces that; `demo/api/index.php` still has 8, outside the
  ruleset's scope.)

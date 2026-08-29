# SECURITY.md

Security posture of the HostelGrievance application after the hardening pass.

Seven confirmed vulnerabilities were remediated: **H-01, H-02, H-03, H-04, H-05, H-06,
H-08.** Each was first reproduced against the running application, then root-caused, then
fixed with the smallest change that closed it, then covered by a test. The per-finding
record — risk, change, verification, residual risk — is in [`HARDENING.md`](HARDENING.md).
The threat model the fixes were designed against is in
[`THREAT-MODEL.md`](THREAT-MODEL.md). Captured verification output is under
[`TEST-EVIDENCE/`](TEST-EVIDENCE/README.md).

Every claim below corresponds to a check that was actually run. Where something could not
be verified in this environment, it is stated as unverified rather than assumed safe.

## What is now protected

**Attachment storage is contained.** Stored filenames are server-generated
(`randomBytes(16).hex` + a MIME-derived extension) and the uploader's filename is never used
as a path — it is kept separately as `original_filename` purely for display. Both the write
and the read path resolve through one helper that rejects `/`, `\`, `..`, and any resolved
path that is not strictly inside the uploads root. Writes use `flag: 'wx'`, so a write fails
rather than overwrites an existing file.

**Grievances enforce object-level authorization.** `GET /:id`, `PATCH /:id`,
`GET /:id/comments`, and `POST /:id/comments` all call `assertCanViewGrievance` after
loading the record: a warden may access any grievance, a student only their own. Attachment
downloads inherit the rules of their parent grievance rather than having rules of their own,
so `GET /api/attachments/:id` is scoped the same way. Guessing a sequential ID
(`GRV-0002`, `att-3`) now returns `403`, not data.

**Status transitions are the warden's alone.** The student branch of `PATCH /:id` rejects
any request carrying a `status` field with `403`, and no longer writes `status` in its
`UPDATE` at all — so the field cannot be smuggled in alongside legitimate content edits.
The check runs before the resolved-state conflict check, so authorization is decided on its
own merits rather than depending on the record's current state.

**Comment bodies are escaped when rendered.** The single `{@html}` in the codebase is gone.
Comment text now takes the same escaped path its sibling fields already took, using Svelte's
own escaping rather than a hand-rolled sanitizer.

**Sessions actually end.** The stored `expires_at` is now compared against the current time
on every session read, and a missing or unparseable expiry counts as expired rather than as
"never expires". Logout deletes the server-side session row before clearing the cookie, so a
token that has been logged out is dead even for someone still holding its value.
`readSessionUser` is the only read path against the `sessions` table, so this is enforced
once for every authenticated route rather than per handler.

**The session cookie carries protective attributes.** `HttpOnly` and `SameSite=Lax`
unconditionally; `Secure` per deployment configuration (see
[Deployment assumptions](#deployment-assumptions)). The cookie-clearing path sends matching
attributes so the deletion actually applies.

## Major changes

Nine files changed — 343 insertions, 35 deletions — plus one new test file. Deliberately
small: the goal was that a reviewer can read the whole diff.

| File | Change |
| --- | --- |
| [`src/server/storage/attachments.ts`](src/server/storage/attachments.ts) | Server-generated stored names; shared `resolveInsideUploads()` containment check on both write and read; non-clobbering `wx` write |
| [`src/server/routes/grievances.ts`](src/server/routes/grievances.ts) | `assertCanViewGrievance` on four handlers; `newStoredName(upload.type)` at the upload call site; student `status` writes replaced with a `403` |
| [`src/server/routes/attachments.ts`](src/server/routes/attachments.ts) | Download authorized against the parent grievance instead of merely checking it exists |
| [`src/server/auth/session.ts`](src/server/auth/session.ts) | Session expiry enforced on read; `HttpOnly` / `SameSite=Lax` / `Secure` on set **and** clear |
| [`src/server/routes/auth.ts`](src/server/routes/auth.ts) | `/logout` destroys the server-side session row |
| [`src/server/config.ts`](src/server/config.ts) | New `SESSION_COOKIE_SECURE`, keyed to `NODE_ENV` with a `HOSTEL_COOKIE_SECURE` override |
| [`src/lib/components/app/comment-timeline.svelte`](src/lib/components/app/comment-timeline.svelte) | `{@html comment.body}` → `{comment.body}` — one line, the only frontend change in the pass |
| [`src/server/app.test.ts`](src/server/app.test.ts) | 9 regression tests added in a new suite; the pre-existing suite untouched |
| [`src/lib/components/app/comment-timeline.test.ts`](src/lib/components/app/comment-timeline.test.ts) | New: 2 AST tests asserting no raw-HTML rendering **and** that the body is still rendered |
| [`vitest.config.ts`](vitest.config.ts) | `include` glob widened additively so the component test is collected — the only configuration change |

Three of these deserve a note on approach:

- **H-02 and H-03 added no new authorization logic.** `assertCanViewGrievance` already
  existed in `src/server/db/queries.ts`, fully written and never called. The fix was to call
  it. Writing a second access rule would have created two sources of truth that could drift.
- **H-01's asymmetry was the tell.** `readStoredFile` already had containment checks;
  `writeStoredFile` had none. The fix factors the existing intent into one helper used by
  both, rather than inventing a new policy.
- **H-04 was fixed at the render boundary, not by sanitizing input.** Escaping on output
  neutralises bodies already stored in the database, needs no allowlist, and adds no
  dependency. Its limit is recorded under [Remaining risks](#remaining-risks).

Nothing was removed to achieve any of this. No feature was disabled, no test was deleted or
weakened, no dependency was added, no technology was replaced, and no UI was redesigned.

## Remaining risks

Stated plainly, because a hardening pass that claims completeness is not credible.

### 1. Comment bodies are stored unsanitized

The H-04 fix is at the **render boundary**. It escapes comment text wherever the timeline
displays it — including bodies already in the database, which is precisely why output
encoding was chosen — but **nothing was sanitized on write, and no stored row was scrubbed.**
Comment rows still contain whatever markup was submitted, verbatim.

The consequence: the application is safe today because exactly one component renders comment
bodies and it escapes them. That safety is a property of the *renderer*, not of the *data*.
Any future consumer that renders a comment body as HTML — a new component using `{@html}`, a
notification email, a PDF or CSV export, an admin view, a template engine without
auto-escaping — reintroduces stored XSS with no new injection required, because the payloads
may already be sitting in the table. There is also no Content-Security-Policy, so there is no
second layer behind the escaping.

Mitigating factors: `HttpOnly` (H-06) now keeps the session token out of reach of page
script, so an XSS no longer hands over the session directly. The AST tests in
`comment-timeline.test.ts` will fail if `{@html}` returns *to that component* — but they
cannot police a component that does not exist yet.

### 2. `Secure` on the session cookie depends on deployment configuration

See [Deployment assumptions](#deployment-assumptions). A deployment served over HTTPS
without `NODE_ENV=production` or `HOSTEL_COOKIE_SECURE=true` ships the session cookie
without `Secure`, silently.

### 3. H-07 and H-09 through H-15 remain open

These were enumerated during reconnaissance and **intentionally not changed in this pass**,
which was scoped to the seven findings above so each change could be verified in isolation.
Their status is unchanged and they should be treated as still exploitable until separately
verified. No test in this repository covers them — the suites were built from the seven
remediated findings, so neither a clean `npm test` nor a fully-blocked attack replay says
anything about the deferred set. `HARDENING.md` records this in full.

One of them bears directly on the controls described above and so is named explicitly: the
CORS configuration in `src/server/app.ts` reflects the request's `Origin` back with
`credentials: true`. `SameSite=Lax` limits what a browser will attach cross-site, but that
policy is the surrounding condition for any cross-origin request and should be addressed
before the application is exposed beyond a trusted network.

### 4. Controls that were out of scope and are therefore absent

Not vulnerabilities that were found and skipped — gaps in the posture, listed so they are
not mistaken for covered ground:

- **No CSRF tokens.** `SameSite=Lax` still permits cross-site top-level `GET`, so it is a
  mitigation, not a replacement.
- **No rate limiting** on login or any other route.
- **No audit log** of status transitions or administrative actions.
- **Absolute 7-day session TTL**, not sliding, with no rotation on privilege change and no
  "log out everywhere". `SESSION_TTL_SECONDS` was left at its pre-existing value.
- **No response-header hardening** on attachment downloads (`Content-Disposition`,
  `X-Content-Type-Options`) and no content inspection of uploaded bytes beyond the
  pre-existing MIME allowlist and size cap.
- **Dependency CVE status unverified.** `npm audit` cannot run here — network egress to
  `registry.npmjs.org` is blocked in this environment. Unverified, not clean. This should be
  run before deployment.

## Deployment assumptions

**Set one of these before serving over HTTPS.** This is the only configuration step this
pass introduced, and getting it wrong reopens part of H-06:

| Deployment | Required setting | Resulting cookie |
| --- | --- | --- |
| Local development (`npm run dev:all`, plain HTTP on `localhost`) | leave both unset | `HttpOnly; SameSite=Lax` |
| Production over HTTPS | `NODE_ENV=production` | `HttpOnly; SameSite=Lax; Secure` |
| HTTPS without `NODE_ENV=production` | `HOSTEL_COOKIE_SECURE=true` | `HttpOnly; SameSite=Lax; Secure` |

`Secure` cannot be unconditional: a `Secure` cookie is dropped over plain HTTP, which would
break login on the project's documented dev server at `http://localhost:5173`. All four
permutations were resolved and recorded in
[`TEST-EVIDENCE/06-session-cookie-matrix.md`](TEST-EVIDENCE/06-session-cookie-matrix.md).
`HOSTEL_COOKIE_SECURE=false` overrides `NODE_ENV=production`, so set it only deliberately.

Beyond that, the pass assumes the application's existing operating model, unchanged:

- **The API is the authorization boundary.** The frontend route guard is the navigation
  boundary; it is not relied on for access control by any fix in this pass. Every one of
  H-01, H-02, H-03, H-05, H-06, and H-08 is enforced server-side.
- **The API server is reached through the app's own origin.** In development, Vite on
  `:5173` proxies `/api` to Hono on `127.0.0.1:3001`; the Hono port is not expected to be
  directly exposed. The permissive CORS policy (risk 3) makes this assumption load-bearing.
- **The uploads directory and the SQLite database are server-private.** Uploads are served
  only through the authorized `GET /api/attachments/:id` route; nothing static-serves the
  directory. `HOSTEL_UPLOADS_DIR` and `HOSTEL_DB_PATH` are trusted operator configuration,
  not user input.
- **Transport security is the deployment's responsibility.** The application does not
  terminate TLS or redirect HTTP to HTTPS.
- **Seeded demo credentials are demo credentials.** The seeded accounts and their passwords
  exist for the challenge dataset and must not survive into any real deployment.

## Verification evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Test suite | 25/25 passing, 2 files | [`01-test-suite.md`](TEST-EVIDENCE/01-test-suite.md) |
| Typecheck | 1007 files, 0 errors, 0 warnings | [`02-typecheck.md`](TEST-EVIDENCE/02-typecheck.md) |
| Attack replay | 15/15 previously-successful exploit steps BLOCKED | [`03-attack-replay.md`](TEST-EVIDENCE/03-attack-replay.md) |
| Workflow verification | 24/24 legitimate student and warden checks PASS | [`04-workflow-verification.md`](TEST-EVIDENCE/04-workflow-verification.md) |
| XSS escaping proof | Escaped emission confirmed against the vulnerable variant | [`05-xss-escaping-proof.md`](TEST-EVIDENCE/05-xss-escaping-proof.md) |
| Cookie `Secure` matrix | 4/4 environment permutations as documented | [`06-session-cookie-matrix.md`](TEST-EVIDENCE/06-session-cookie-matrix.md) |

Two properties of this evidence are worth stating:

**The fixes were validated in both directions.** The attack replay proves the exploits no
longer work; the workflow verification proves the features still do. An over-broad
authorization fix would pass the first and fail the second — four of the nine new API tests
exist specifically to assert that *legitimate* access still succeeds, so a fix that
over-blocked would fail loudly rather than look secure.

**Five of the seven findings were specified by tests that already existed.** The repository
shipped with five failing tests, each an accurate statement of behaviour the application did
not implement. Those five now pass **unmodified** — the application was changed, not the
tests. The remaining two findings (H-01, H-04) plus H-06 had no baseline coverage and are
covered by the 11 tests added.

Reproduction:

```bash
npm run typecheck && npm test
```

```bash
node TEST-EVIDENCE/scripts/attack-replay.ts
```

```bash
node TEST-EVIDENCE/scripts/workflow-verification.ts
```

The harness scripts seed a throwaway database and uploads directory under the OS temp
directory and remove them on exit; the repository's `data/hostel.db` and `uploads/` are
untouched. Each exits `0` on success and non-zero on any failure. Environment and the
remaining two scripts are documented in
[`TEST-EVIDENCE/README.md`](TEST-EVIDENCE/README.md).

## Blast radius if one important control fails

What breaks, and how far, if a single control is regressed or bypassed. This is the
composition question — the reason H-04 and H-06 were fixed as a pair.

| Control | If it fails | Blast radius | What still holds |
| --- | --- | --- | --- |
| **`assertCanViewGrievance`** (`src/server/db/queries.ts`, called from 5 handlers) | Any authenticated student reads, comments on, and edits every grievance by walking sequential IDs | **Widest of any single control.** It is the only thing standing between an ordinary student account and the entire dataset — every complaint body, plus the personal details H-02 was observed leaking. Recovering both H-02 and H-03 requires only that this one function stop being called; the routes' shape is otherwise unchanged, so an accidental drop during a future refactor is a realistic failure, which is exactly how the original vulnerability existed | Warden-only status transitions (H-08 is a separate check); attachment path containment; session expiry. Four regression tests fail immediately |
| **`resolveInsideUploads`** (`src/server/storage/attachments.ts`) | Attacker-controlled bytes land at an attacker-chosen path with the server's privileges | **Highest severity, deepest layer.** Escapes the application boundary entirely: overwritten application files, destroyed attachments, potential code execution depending on what is writable. Not contained by any authorization control, because triggering it needs nothing more than an upload to one's own grievance | Nothing above it helps. The two mitigations are independent: stored names are server-generated so no user string reaches the path in the first place, and `wx` refuses to overwrite even if a name did — both must fail together for the original impact |
| **Output escaping of comment bodies** (comment timeline) | Stored XSS returns — and, because bodies were never sanitized, **possibly with payloads already in the database**, needing no new injection | Script in the browser of every viewer of that timeline, including the warden. **`HttpOnly` is what bounds this**: with it, the session token cannot be read out, so the ceiling is actions within the victim's live session rather than durable account takeover. Without both controls it was full warden compromise from a student comment | `HttpOnly` (independent, in `src/server/auth/session.ts`) and server-side authorization on every request. There is no CSP as a third layer |
| **`readSessionUser`'s expiry check** | Every session becomes immortal again across the whole API | **Every authenticated route at once** — this is the single read path against the `sessions` table, which is what makes the fix cheap and the failure broad. Combined with a logout-invalidation regression, a captured token is permanent | Server-side row deletion on logout is a separate mechanism: a logged-out token stays dead even if the expiry check is lost. Two tests fail |
| **`destroySession` on logout** | Logout becomes cosmetic again; tokens outlive it | Bounded by the 7-day TTL rather than unbounded, provided the expiry check holds — the two H-05 mechanisms deliberately back each other up | The expiry check; `HttpOnly` limiting how a token gets captured in the first place |
| **`SESSION_COOKIE_SECURE` misconfigured** (HTTPS with neither flag set) | Session cookie ships without `Secure` | Token interceptable on any plain-HTTP or downgraded request to the same host, leading to session hijacking. **Fails silently — no error, no warning, and the application works normally**, which makes it the most likely of these to go unnoticed | `HttpOnly` and `SameSite=Lax`, which are unconditional and unaffected; session expiry and logout invalidation still bound a stolen token's lifetime |
| **H-08's status role gate** | Students resolve their own grievances again | Integrity of the warden's queue: the record of what was actually handled becomes forgeable. No confidentiality impact on its own — but combined with an `assertCanViewGrievance` failure it extends to *every* student's grievance | `assertCanViewGrievance` confines the damage to the attacker's own records; the resolved-state `409` still applies to content edits |

Two patterns follow from the table. First, the controls are **layered rather than
redundant** — H-01 and H-05 each have two independent mechanisms that must both fail for
the original impact to return, while `assertCanViewGrievance` and the escaping have no
backstop behind them and are therefore the ones to protect in review. Second, the failure
that is hardest to notice is not the most severe one: a missing `Secure` attribute produces
no symptom at all, whereas losing `assertCanViewGrievance` breaks four tests on the next
run.

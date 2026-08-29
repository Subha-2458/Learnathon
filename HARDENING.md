# HARDENING.md

Remediation record for the HostelGrievance security-hardening pass.

Seven findings were fixed: **H-01, H-02, H-03, H-04, H-05, H-06, H-08.** Each had been
confirmed by exercising the running application during reconnaissance, before any file was
modified. Nothing in this document is projected, inferred from a scanner, or assumed —
every entry in the Verification column corresponds to a check that was executed and whose
output is recorded under [`TEST-EVIDENCE/`](TEST-EVIDENCE/README.md).

Scope discipline: **9 files changed, 343 insertions, 35 deletions**, plus one new test file.
No feature was removed, no test was deleted or weakened, no dependency was added, and no
UI was redesigned.

## Remediated findings

| ID | Finding | Risk | Change | Verification | Residual Risk |
| --- | --- | --- | --- | --- | --- |
| **H-01** | Arbitrary file write via attachment upload filename. `newStoredName(mime, originalName?)` returned `originalName ?? random`, so the uploader's filename became the on-disk name, and `writeStoredFile` joined it to the uploads directory with no containment check. Confirmed: an upload named `../../ESCAPED-WRITE.png` was written two levels above the uploads root and recorded in the DB as `stored_filename: ../../ESCAPED-WRITE.png`; a second upload named after an existing stored file replaced its contents with `OVERWRITTEN`. | **Critical.** Authenticated write of attacker-controlled bytes to an attacker-chosen path with the server process's privileges — code/config overwrite, and destruction of other users' attachments. Reachable by any student with an account, on their own grievance, so no authorization flaw was needed to trigger it. | `src/server/storage/attachments.ts`: `newStoredName` no longer accepts a filename and always returns `randomBytes(16).hex + extensionForMime(mime)`. New private `resolveInsideUploads()` rejects empty names, `/`, `\`, `..`, and any resolved path that is not strictly inside the uploads root; `writeStoredFile` and `readStoredFile` both go through it. `writeStoredFile` uses `writeFileSync(..., { flag: 'wx' })` so a write fails rather than overwrites. `src/server/routes/grievances.ts`: call site becomes `newStoredName(upload.type)`; the uploader's name is still stored as `original_filename` via `originalBasename(upload.name)` for display. | `does not let an upload filename escape the uploads directory`, `does not overwrite an existing stored file via the upload filename` (both new). Attack replay: `H-01 traversal write escapes uploads dir` → BLOCKED (`stored=f3a14b2ed807031244d72b227d0ec6a6.png`), `uploads dir contains only server-generated names` → BLOCKED, `overwrite of existing stored file` → BLOCKED with `Buffer.equals` against a pre-attack copy. Upload still returns `201` and `filename` still returns `my photo.png` in [`04`](TEST-EVIDENCE/04-workflow-verification.md). | Stored bytes are still trusted content served back with the client-supplied `mime_type`. Upload type and size limits (`ALLOWED_ATTACHMENT_TYPES`, `MAX_ATTACHMENT_BYTES`) are pre-existing and were not changed; no antivirus or magic-byte validation was added, as that was outside this pass. |
| **H-02** | Broken object-level authorization on grievances. `assertCanViewGrievance` existed in `src/server/db/queries.ts` but was never called; `GET /:id`, `PATCH /:id`, `GET /:id/comments`, and `POST /:id/comments` used `requireGrievance` for existence only, and three of them discarded the `requireUser` result entirely. Confirmed: `student@example.test` read `GRV-0003` (owned by `priya@example.test`) and received `200` including that student's email address and room number. | **High.** Any authenticated student could read, comment on, and modify every other student's grievance by ID. Grievance IDs are sequential (`GRV-0001`…), so the whole dataset was enumerable — a disclosure of personal complaint content plus contact and room details, and a tampering path into other students' records. | `src/server/routes/grievances.ts`: `assertCanViewGrievance(user, row)` added immediately after `requireGrievance` in all four handlers, and `const user = requireUser(c, db)` now binds the result where it had been thrown away. No new authorization logic was written — the existing helper (warden → allow; student → allow only own `student_id`) is the single source of truth. `POST /:id/attachments` was already owner-scoped and was not touched. | `does not let a student read or comment on another student's grievance` and `still lets the owning student and the warden use the comment workflow` (both new). Two pre-existing baseline tests that had been failing — `student cannot access another student's grievance` and `lets a student edit their own open grievance but not a resolved one` — now pass unmodified. Attack replay: four cross-student steps → BLOCKED (`403`). | Authorization is per-request and correct for the owner/warden model, but the model itself is coarse: any warden can read every grievance, which is intended behaviour here. Grievance IDs remain sequential and enumerable — now they return `403` rather than data, so the residual leak is existence, not content. |
| **H-03** | Attachment downloads were not scoped to the grievance's audience. `GET /api/attachments/:id` called `requireUser` but discarded the result, and called `requireGrievance` purely to confirm the parent existed. Confirmed: `priya@example.test` downloaded `att-1`, which belongs to a grievance owned by `student@example.test`, receiving `200` and 202 bytes of file content. | **High.** Any authenticated user could download any attachment by ID, bypassing the grievance boundary entirely. Attachment IDs are sequential (`att-1`…). Attachments are the most sensitive artefact in the app — photographs and documents supporting a complaint — and this path leaked them directly as bytes. | `src/server/routes/attachments.ts`: `const user = requireUser(c, db)` now binds, and the existence check became the authorization check: `assertCanViewGrievance(user, requireGrievance(db, row.grievance_id))`. An attachment inherits the access rules of its parent grievance rather than having rules of its own. | `scopes attachment downloads to users authorised for the grievance` (new) — asserts `403` for the unauthorised student while asserting the owner and the warden both still succeed. The pre-existing baseline test `attachment metadata and storage work`, which had been failing on its cross-student assertion, now passes unmodified. Attack replay: `H-03 download another student attachment` → BLOCKED. `04` confirms `owner downloads own attachment byte-for-byte` and `warden downloads any attachment`. | Attachment bytes are served with the stored `mime_type` and no `Content-Disposition` or `X-Content-Type-Options` header; that response-header hardening was not in this pass. Authentication was already required on this route and remains so (`H-03 anonymous attachment download` in the replay is a control confirming that, not a hole that was closed). |
| **H-04** | Stored cross-site scripting. `src/lib/components/app/comment-timeline.svelte:49` rendered `{@html comment.body}` — the only `{@html}` in the codebase — while every sibling field in the same element (`author.name`, `author.role`, timestamp) was escaped normally. Comment bodies are free text written by students and the warden and are stored verbatim. | **High.** Any user who can comment on a grievance could inject script that executes in the browser of everyone who later views that grievance's timeline — including the warden, whose session is the highest-privileged in the application. That is a direct student → warden privilege-escalation path, and it compounded with H-06: the session cookie had no `HttpOnly`, so injected script could read the token outright. | One token: `{@html comment.body}` → `{comment.body}`. A single-line diff; the six-tab indentation of the original line was preserved deliberately so the change is exactly one line. No sanitizer, no allowlist, no dependency — Svelte's own escaping. Newlines still render because the pre-existing `whitespace-pre-line` class, not markup, was already handling them. | Two new AST tests in `src/lib/components/app/comment-timeline.test.ts`: `never renders any part of a comment as raw HTML` (no `HtmlTag` node anywhere in the template) and `still renders the comment body through an escaped expression` (the body is still present, via an `ExpressionTag`) — the second exists so the guard cannot be satisfied by deleting the feature. Negative-controlled during implementation by reintroducing `{@html}`: both tests failed, then reverted. Compiler-level proof in [`05`](TEST-EVIDENCE/05-xss-escaping-proof.md): the SSR output emits `$.escape(comment.body)`, and the vulnerable variant compiled in memory emits `$.html(comment.body)`. | **The fix is at the render boundary, not at the data boundary.** It neutralises every comment body wherever the timeline displays it, including bodies already sitting in the database, but comment rows still contain whatever markup was submitted — nothing was sanitized on write and nothing was scrubbed retroactively. Any future consumer that renders a comment body as HTML, exports it into another document, or pipes it into a template that does not escape would reintroduce this vulnerability. No Content-Security-Policy was added, so there is no second layer behind the escaping. |
| **H-05** | Session lifecycle was not enforced on either end. `readSessionUser` selected `expires_at` from the row and never compared it to the current time, so sessions never expired. `POST /api/logout` called `clearSessionCookie` only; `destroySession` existed in `src/server/auth/session.ts` but was never called, so the server-side row survived logout. Confirmed: `/api/me` returned `200` with the session's `expires_at` set to `2000-01-01`, and returned `200` again when the cookie value was replayed after a successful logout. | **High.** Session tokens were effectively immortal bearer credentials. Logout was cosmetic — it cleared the browser's copy and nothing else — so a token captured from a shared machine, a log, a proxy, or (given H-06) page script remained valid indefinitely, with no user-accessible way to revoke it. | `src/server/auth/session.ts`: `readSessionUser` now parses `expires_at` and returns `undefined` when it is missing, unparseable, or in the past — a malformed expiry counts as expired rather than as "never expires". `src/server/routes/auth.ts`: `/logout` now reads the presented token with `optionalToken` and calls `destroySession` before clearing the cookie. `readSessionUser` was confirmed by grep to be the only read path against the `sessions` table, so this one check governs every authenticated route. | `rejects a session whose stored expiry has passed` and `invalidates the server-side session on logout` (both new); the second asserts the `sessions` row count for the token is `0`, so invalidation is proven server-side rather than by response code alone. The pre-existing baseline test `current-user works after login and fails after logout`, which had been failing, now passes unmodified. Attack replay: expired-session use, post-logout replay, and row survival → all BLOCKED. `04` confirms `logout 200`, `replayed token rejected after logout`, `can log in again after logout`. | Expiry is absolute, not sliding, and `SESSION_TTL_SECONDS` remains the pre-existing 7 days — a long window for a stolen token, unchanged because changing it would alter intended behaviour. Expired rows are rejected on read but not reaped from the table; that is a housekeeping matter, not an access-control one. There is no "log out everywhere", no rotation on privilege change, and no rate limiting on login — none of which were in this pass's scope. |
| **H-06** | Session cookie was set with only `path` and `maxAge`. The raw response header observed was `Set-Cookie: hg_session=…; Max-Age=604800; Path=/` — no `HttpOnly`, no `SameSite`, no `Secure`. `clearSessionCookie` likewise sent only `path`. | **High.** Without `HttpOnly`, any script execution in the page — H-04 being a live instance — could read the session token directly, turning an XSS into full account takeover. Without `SameSite`, any external site could drive authenticated state-changing requests from a logged-in browser. Without `Secure`, the token would travel over plain HTTP on an HTTPS deployment. | `src/server/auth/session.ts`: `setSessionCookie` adds `httpOnly: true`, `sameSite: 'Lax'`, and `secure: SESSION_COOKIE_SECURE`. `clearSessionCookie` sends the same three attributes so the deletion actually matches the cookie that was set — mismatched attributes can leave the browser holding the original, which would have undermined H-05 from the client side. `src/server/config.ts`: new `SESSION_COOKIE_SECURE`, defaulting to `NODE_ENV === 'production'` and overridable in either direction with `HOSTEL_COOKIE_SECURE`. `Path` and `Max-Age` are unchanged. | `sets HttpOnly and SameSite on the session cookie` (new). `04` records the real dev-mode header: `hg_session=…; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax`. [`06`](TEST-EVIDENCE/06-session-cookie-matrix.md) resolves all four environment permutations in clean child processes: dev → `secure=false`, `NODE_ENV=production` → `secure=true`, explicit `false` overrides production, explicit `true` works without `NODE_ENV`. | **`Secure` is configuration-dependent and a misconfigured deployment silently omits it** — see the deployment requirement below; this is the one residual risk in this table that must be closed by the deployer rather than by code. `SameSite=Lax` was chosen over `Strict` because `Strict` breaks normal top-level navigation into the app; `Lax` still permits cross-site top-level `GET`, so it is not a substitute for CSRF tokens on state-changing routes, and no CSRF token scheme was added in this pass. The CORS policy in `src/server/app.ts` was not part of this pass and is unchanged. |
| **H-08** | Privilege escalation through the grievance update route. In `PATCH /api/grievances/:id`, the `case 'student'` branch accepted a `status` field and applied `statusToDb(status)` with no role check, writing `status = ?` in the same `UPDATE` as the content fields. Confirmed: a student `PATCH`ed their own grievance to `Resolved` and received `200`. This directly contradicted the application's own student-facing text, "Only the warden can change the status of a grievance." | **High.** Students could resolve their own complaints, and — before H-02 was fixed — anyone else's. That destroys the integrity of the warden's workflow: the grievance queue is the record of what has actually been handled, and a student could clear items out of it or fabricate a resolution history. | `src/server/routes/grievances.ts`: the student branch now throws `403 unauthorized` when a `status` field is present. The check is placed **before** the resolved-state `409`, so an unauthorised field is rejected on its own merits rather than depending on the record's current state. The dead `nextStatus` variable, the `status !== undefined` block, and `status = ?` were removed, leaving `UPDATE grievances SET title = ?, description = ?, category = ?, updated_at = ? WHERE id = ?`. The now-unused `GrievanceStatusDb` type import was dropped; `statusToDb` remains, still used by the warden branch. | `refuses student status changes but keeps student content edits working` (new) — asserts `403` for `{status}` alone and for `status` smuggled alongside `title`, reads the record back to confirm no partial write, and asserts a title-only edit still returns `200`. The pre-existing baseline test `status changes work for wardens and are forbidden for students`, which had been failing, now passes unmodified. Attack replay: both direct and smuggled attempts → BLOCKED. `04` confirms `warden changes status`, `warden resolves grievance`, `student sees warden status change`, and `resolved grievance still 409 for student content edit`. | Status transitions are now warden-only but remain unconstrained in shape — any warden may move a grievance to any status in any order, and no transition history or audit log is written. Both were pre-existing behaviour and changing either would have altered intended business logic. |

## Deployment requirement — `SESSION_COOKIE_SECURE`

The `Secure` attribute added by H-06 is **not unconditional**, and this is the single
configuration item that must be handled correctly at deploy time or an H-06-class weakness
returns:

| Deployment | Required setting | Resulting cookie |
| --- | --- | --- |
| Local development (`npm run dev:all`, plain HTTP on `localhost`) | leave both unset | `HttpOnly; SameSite=Lax` — no `Secure` |
| Production over HTTPS | `NODE_ENV=production` | `HttpOnly; SameSite=Lax; Secure` |
| HTTPS **without** `NODE_ENV=production` | `HOSTEL_COOKIE_SECURE=true` | `HttpOnly; SameSite=Lax; Secure` |

`Secure` is conditional because it has to be: a `Secure` cookie is dropped by the browser
over plain HTTP, so hardcoding it would break login on the project's documented development
server at `http://localhost:5173`.

**The failure mode to guard against: serving the application over HTTPS without setting
either `NODE_ENV=production` or `HOSTEL_COOKIE_SECURE=true`.** `SESSION_COOKIE_SECURE`
resolves to `false`, the cookie ships without `Secure`, nothing errors or warns, and the
session token becomes interceptable on any plain-HTTP or downgraded request to the same
host. `HOSTEL_COOKIE_SECURE=true` is the supported fix when `NODE_ENV` cannot be changed.

`HOSTEL_COOKIE_SECURE=false` overrides `NODE_ENV=production` (row 3 of the matrix in
[`06`](TEST-EVIDENCE/06-session-cookie-matrix.md)). It exists so an unusual deployment can
opt out deliberately, and should be set only with intent.

`HttpOnly` and `SameSite=Lax` are unconditional and require no configuration.

## Findings deliberately left open

**H-07 and H-09 through H-15 remain open. They were not changed in this pass, and their
status is exactly what reconnaissance recorded.**

This was scope, not an assessment that they are harmless. The fix pass was explicitly
limited to the seven findings above so that each change could be inspected, root-caused,
minimally fixed, tested, and workflow-verified in isolation. Accordingly:

- No code, configuration, or dependency relating to H-07 or H-09–H-15 was modified.
- No test was added for them, and no test result in this repository should be read as
  covering them.
- Their content is not restated here. It belongs to the reconnaissance report for this
  engagement, and paraphrasing findings that were not re-examined during this pass would
  risk misstating them.
- **They should be treated as still exploitable until separately verified.** A clean
  `npm test` and a fully-`BLOCKED` attack replay speak only to H-01–H-06 and H-08; both
  suites were built from those findings and neither exercises the deferred ones.

One deferred item is worth naming explicitly, because it changes how the H-06 cookie
controls should be read rather than sitting independently of them: the CORS configuration
in `src/server/app.ts` reflects the request's `Origin` back with `credentials: true`, which
was observed during reconnaissance and is unchanged. `SameSite=Lax` limits what a browser
will send cross-site, but the permissive CORS policy remains the surrounding condition for
any cross-origin work, and it should be addressed before this application is exposed
beyond a trusted network.

## What was explicitly not done

Recorded so the diff can be read with confidence about its boundaries:

- No UI redesign, and no change to visual appearance, layout, styling, navigation, or user
  experience. The only frontend change in the entire pass is the removal of `{@html}` from
  one interpolation, whose rendered output for legitimate text is identical.
- No feature removed or disabled. Grievance creation, grievance viewing, comments,
  attachments, student workflows, and warden workflows are all confirmed working in
  [`04`](TEST-EVIDENCE/04-workflow-verification.md).
- No test deleted, skipped, weakened, or rewritten to pass. The five pre-existing failures
  were fixed in the application, not in the tests. The pre-existing suite is byte-identical.
- No business logic changed except where the existing behaviour *was* the vulnerability
  (H-08's missing role gate).
- No technology replaced and no dependency added. Svelte, Hono, SQLite, and Vite are as
  they were; the new tests use `svelte/compiler`, which the project already depends on.
- No backend problem solved in the frontend. H-01, H-02, H-03, H-05, H-06, and H-08 are all
  server-side fixes.
- One configuration change only: `vitest.config.ts`'s `include` glob was widened additively
  so the new component test is actually collected.
- One unverifiable area, stated rather than glossed: `npm audit` could not run in this
  environment (network egress to `registry.npmjs.org` is blocked), so the dependency tree's
  CVE status is **unverified**, not clean.

## Verification summary

| Check | Result |
| --- | --- |
| `npm test` | 25/25 passing across 2 files — [`01`](TEST-EVIDENCE/01-test-suite.md) |
| `npm run typecheck` | 1007 files, 0 errors, 0 warnings — [`02`](TEST-EVIDENCE/02-typecheck.md) |
| Attack replay | 15/15 previously-successful exploit steps BLOCKED — [`03`](TEST-EVIDENCE/03-attack-replay.md) |
| Workflow verification | 24/24 legitimate student and warden checks PASS — [`04`](TEST-EVIDENCE/04-workflow-verification.md) |
| XSS escaping proof | Escaped emission confirmed against the vulnerable variant — [`05`](TEST-EVIDENCE/05-xss-escaping-proof.md) |
| Cookie `Secure` matrix | 4/4 environment permutations as documented — [`06`](TEST-EVIDENCE/06-session-cookie-matrix.md) |

Reproduction commands and environment details are in
[`TEST-EVIDENCE/README.md`](TEST-EVIDENCE/README.md).

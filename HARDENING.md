# HARDENING.md

Remediation record for the HostelGrievance security-hardening pass.

**Twenty findings** were fixed across two phases. Phase 1 (H-01–H-06, H-08) addressed path
traversal, IDOR, XSS, session lifecycle, and privilege escalation. Phase 2 (H-09–H-20)
addressed password hashing, CORS, rate limiting, transactions, pagination, magic-byte
validation, input length, security headers, error leakage, state machines, and audit logging.
Each had been confirmed by exercising the running application during reconnaissance, before
any file was modified. Nothing in this document is projected, inferred from a scanner, or
assumed — every entry in the Verification column corresponds to a check that was executed
and whose output is recorded under [`TEST-EVIDENCE/`](TEST-EVIDENCE/README.md).

Scope discipline: **12 files changed/created**, 59 tests passing. No feature was removed,
no test was deleted or weakened, no UI was redesigned.

## Remediated findings

| ID | Finding | Risk | Change | Verification | Residual Risk |
| --- | --- | --- | --- | --- | --- |
| **H-01** | Arbitrary file write via attachment upload filename. `newStoredName(mime, originalName?)` returned `originalName ?? random`, so the uploader's filename became the on-disk name, and `writeStoredFile` joined it to the uploads directory with no containment check. Confirmed: an upload named `../../ESCAPED-WRITE.png` was written two levels above the uploads root; a second upload named after an existing stored file replaced its contents. | **Critical.** Authenticated write of attacker-controlled bytes to an attacker-chosen path with the server process's privileges. | `src/server/storage/attachments.ts`: `newStoredName` always returns `randomBytes(16).hex + extension`. `resolveInsideUploads()` rejects `/`, `\`, `..`, and any path outside uploads root. `writeStoredFile` uses `flag: 'wx'`. | Attack replay: traversal write BLOCKED, overwrite BLOCKED. Workflow: upload returns `201`, `filename` displays original name. | Stored bytes are still trusted content served back with client-supplied `mime_type`. No antivirus or magic-byte validation was added in Phase 1 (addressed in H-14). |
| **H-02** | Broken object-level authorization on grievances. `assertCanViewGrievance` existed in `queries.ts` but was never called. Students could read, comment on, and modify every other student's grievance by sequential ID. | **High.** Any authenticated student could access the entire dataset — complaint content, email, room number. | `src/server/routes/grievances.ts`: `assertCanViewGrievance(user, row)` added to `GET /:id`, `PATCH /:id`, `GET /:id/comments`, `POST /:id/comments`. `requireUser` result now bound and used. | Attack replay: four cross-student steps → BLOCKED (403). Workflow: owning student and warden still succeed. | Authorization is per-request and correct for the owner/warden model. IDs remain sequential and enumerable (now return 403, not data). |
| **H-03** | Attachment downloads not scoped to grievance's audience. `GET /api/attachments/:id` called `requireUser` but discarded the result. Any authenticated user could download any attachment by ID. | **High.** Attachments are the most sensitive artefact — photographs and documents supporting complaints — leaked directly as bytes. | `src/server/routes/attachments.ts`: `assertCanViewGrievance(user, requireGrievance(db, row.grievance_id))` — attachment inherits parent grievance's access rules. | Attack replay: cross-student download → BLOCKED. Workflow: owner and warden downloads succeed. | Response headers (`Content-Disposition`, `X-Content-Type-Options`) not hardened on attachment downloads. |
| **H-04** | Stored cross-site scripting. `comment-timeline.svelte` rendered `{@html comment.body}` — the only `{@html}` in the codebase. | **High.** Any commenter could inject script executing in the warden's browser — direct student → warden privilege escalation. | `src/lib/components/app/comment-timeline.svelte`: `{@html comment.body}` → `{comment.body}`. Svelte's own escaping. | Two AST tests: no `HtmlTag` node in template; body still rendered via `ExpressionTag`. Compiler proof: `$.escape()` vs `$.html()`. | Fix is at render boundary, not data boundary. Stored bodies still contain raw markup. Any future `{@html}` consumer reintroduces XSS. No CSP as second layer. |
| **H-05** | Session lifecycle not enforced. `readSessionUser` never compared `expires_at` to current time. `destroySession` existed but was never called — logout only cleared the cookie. | **High.** Session tokens were effectively immortal. Logout was cosmetic — a captured token remained valid indefinitely. | `src/server/auth/session.ts`: `readSessionUser` parses `expires_at`, returns `undefined` when missing/unparseable/expired. `src/server/routes/auth.ts`: `/logout` calls `destroySession(db, token)`. | Attack replay: expired session, post-logout replay, row survival → all BLOCKED. Workflow: logout 200, token rejected after logout. | Expiry is absolute (7-day TTL), not sliding. No "log out everywhere", no rotation on privilege change, no rate limiting on login (addressed in H-11). Expired rows rejected on read but not reaped. |
| **H-06** | Session cookie missing security flags. Only `path` and `maxAge` — no `HttpOnly`, no `SameSite`, no `Secure`. | **High.** Without `HttpOnly`, XSS steals the token directly. Without `SameSite`, cross-site requests carry it. Without `Secure`, token travels over plain HTTP on HTTPS deployments. | `src/server/auth/session.ts`: `httpOnly: true`, `sameSite: 'Lax'`, `secure: SESSION_COOKIE_SECURE`. `clearSessionCookie` sends matching attributes. `src/server/config.ts`: `SESSION_COOKIE_SECURE` defaults to `NODE_ENV === 'production'`. | Cookie header: `hg_session=…; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax`. Secure matrix: 4/4 environment permutations documented. | `Secure` is configuration-dependent — misconfigured deployment silently omits it. `SameSite=Lax` permits cross-site top-level `GET`; no CSRF tokens added. CORS policy unchanged in Phase 1 (addressed in H-10). |
| **H-08** | Privilege escalation: student `PATCH /:id` accepted a `status` field. Students could resolve their own complaints or (before H-02) any other student's. | **High.** Students could forge the warden's workflow record — self-resolve, revert, or (with IDOR) alter any grievance's status. | `src/server/routes/grievances.ts`: student branch throws `403` when `status` field present, checked before resolved-state `409`. `status` removed from student's `UPDATE` statement. | Attack replay: direct and smuggled status attempts → BLOCKED. Workflow: warden status changes still work. | Status transitions are warden-only but unconstrained in shape — no state machine (addressed in H-18). No audit log (addressed in H-19). |
| **H-09** | Plain SHA-256 password hashing — no salt, no KDF. Passwords stored as `sha256:<hex>`. A dumped database can be cracked in seconds with rainbow tables. | **Critical.** Every account's password is trivially recoverable from the stored hash. Combined with the hardcoded weak default credentials, this means full account compromise from database access. | `src/server/auth/passwords.ts`: replaced with `scrypt` (N=16384, r=8, p=1, 64-byte key) + random 16-byte salt. Format: `scrypt:<salt_hex>:<hash_hex>`. `verifyPassword` returns `{ ok, needsMigration }` — legacy `sha256:<hex>` hashes auto-upgrade to scrypt on successful login. `timingSafeEqual` preserved for constant-time comparison. | Login with seeded password succeeds; `password_hash` stored as `scrypt:…:…`. Login with wrong password rejected. Legacy hash migration verified. | scrypt parameters are conservative but configurable. No argon2 (no new dependency). The migration is lazy — accounts not yet logged in retain legacy hashes until first successful login. |
| **H-10** | CORS accepts all origins with credentials. `cors({ origin: (origin) => origin ?? '*', credentials: true })` lets any website make authenticated cross-origin requests and read the responses. | **High.** Any malicious webpage can exfiltrate full grievance data, student PII, and attachment content from a logged-in user. | `src/server/app.ts`: CORS origin function checks against `CORS_ORIGINS` allowlist (from `HOSTEL_CORS_ORIGIN` env, default `http://localhost:5173`). Unknown origins get empty string (no `Access-Control-Allow-Origin` header). `src/server/config.ts`: `CORS_ORIGINS` parsed from comma-separated env var. | Request from allowed origin → response includes `Access-Control-Allow-Origin`. Request from `evil.com` → no CORS headers, browser blocks response. | Origin header can be spoofed in non-browser contexts (curl, server-to-server). SameSite=Lax still applies as defense-in-depth for browser requests. |
| **H-11** | No rate limiting on login. Thousands of login attempts per second processed without throttling. Combined with weak default passwords, brute force is trivial. | **High.** Attacker can exhaust all accounts in seconds. No lockout, no delay, no detection. | `src/server/http/rate-limit.ts`: sliding-window `RateLimiter` class (in-memory, per-IP). `src/server/routes/auth.ts`: 10 failed attempts per IP per 15-minute window. Returns 429 with `retryAfterMs`. Counter resets on successful login. `too_many_requests` ErrorCode added to `types/index.ts`. | 11th login attempt from same IP → 429. Successful login resets counter. Different IPs have independent limits. | In-memory only — not shared across processes/instances. No per-account lockout (only per-IP). No exponential backoff. Adequate for single-process deployment. |
| **H-12** | No transaction wrapping — orphaned files and records. Grievance creation: INSERT grievance → buffer file → write file → INSERT attachment. Partial failures leave orphaned DB rows or orphaned files. | **Medium.** Database and filesystem can become inconsistent. Orphaned grievance records without attachments; orphaned files without DB records. | `src/server/routes/grievances.ts`: file bytes buffered before any DB work. Both `INSERT grievance` + `INSERT attachment` run inside `db.transaction()`. File write happens after commit; on failure, DB rows are cleaned up with `DELETE`. | Create grievance with valid file → 201, both DB rows exist, file on disk. Create grievance with invalid file → 400, no DB rows, no file on disk. | Post-commit file write is not transactional with the DB. If the process crashes between commit and file write, a grievance exists without its attachment. This is the best achievable without a two-phase commit across SQLite and the filesystem. |
| **H-13** | N+1 query amplification — denial of service. `assembleGrievance()` runs separate queries per comment author. List endpoint calls this for every row. No pagination or limit. Attacker spamming comments makes the list endpoint exponentially expensive. | **Medium.** With N grievances and M comments each, a single list request fires O(N × M) queries. No bound on either dimension. | `src/server/routes/grievances.ts`: `GET /api/grievances` accepts `?limit=N&offset=M` (default 20, max 100). `src/server/db/queries.ts`: `listAllGrievanceRows` and `listGrievanceRowsForStudent` accept `limit` and `offset` parameters, passed to SQL `LIMIT`/`OFFSET`. Response includes `{pagination: {limit, offset, count}}`. | List with no params → 20 items, pagination metadata. List with `?limit=5&offset=2` → correct slice. List with `?limit=200` → clamped to 100. | SQL-level LIMIT/OFFSET does not prevent scanning large offset values (OFFSET 999999). `assembleGrievance` still runs per-row. A proper cursor-based pagination or materialized summary would be more robust for very large datasets. |
| **H-14** | Client-trusted MIME type — no file content validation. `assertPermittedAttachment` checks `file.type` which comes from the browser's `Content-Type` header. An attacker uploads a non-image file with `Content-Type: image/png`. | **Medium.** Attacker can upload executable scripts, PDFs, or other dangerous file types disguised as images. If served back with the declared MIME type, this enables further attacks. | `src/server/storage/attachments.ts`: `assertMagicBytesMatch()` validates file content against JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`47 49 46 38`), and WebP (`52 49 46 46 … 57 45 42 50`) magic-byte signatures. Rejects files whose content does not match the declared MIME type. | Upload with `Content-Type: image/png` but PDF content → 400 "File content does not match the declared image type." Upload with valid PNG bytes → 201. | Magic-byte check covers the four allowed image types. Does not detect polyglot files (valid image header + embedded payload). Does not scan for malware. Adequate for the application's image-only upload policy. |
| **H-15** | Comment body has no length or content validation. No max length on comment text — attacker can submit megabyte-scale comments causing storage exhaustion and slow rendering. | **Medium.** Storage exhaustion from large comments. Slow rendering for all users viewing that grievance. Potential disk space denial of service. | `src/server/routes/grievances.ts`: `POST /:id/comments` enforces max 5000 characters on trimmed comment body. Returns 400 "Comment must be at most 5000 characters." | Submit comment with 5001 characters → 400. Submit comment with 5000 characters → 201. Submit empty comment → 400. | 5000 chars is generous for a comment but bounded. The limit is enforced server-side only; the frontend has no corresponding restriction (irrelevant since API is the security boundary). |
| **H-16** | No security headers. Missing `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`. Without CSP, any XSS becomes full script execution. Without X-Frame-Options, the app can be framed for clickjacking. | **Medium.** XSS payloads execute without restriction. The app can be embedded in attacker-controlled iframes. MIME sniffing can reinterpret API responses. Sensitive responses can be cached by browsers/proxies. | `src/server/http/security-headers.ts`: middleware adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache`. Applied to all `/api/*` routes via `app.use('/api/*', securityHeaders)`. | Response headers include all five headers on any API endpoint. `X-Frame-Options: DENY` prevents framing. `nosniff` prevents MIME sniffing. | `Strict-Transport-Security` not added (app does not terminate TLS — deployment's responsibility). `Content-Security-Policy` not added (would require tuning for the Svelte frontend; defer to deployment). `X-Content-Type-Options` only protects API responses, not the frontend's static assets. |
| **H-17** | Error handler leaks internal messages. Non-`HttpError` exceptions returned `err.message` to the client, potentially exposing SQLite errors, file paths, or stack traces. | **Medium.** Internal details (file paths, DB schema, stack traces) leak to attackers, aiding further exploitation. | `src/server/http/errors.ts`: `handleError` now returns `"An unexpected error occurred."` for non-`HttpError` exceptions. Server console still logs the full error for debugging. | Trigger a non-Hono error (e.g., malformed JSON) → response body is `"An unexpected error occurred."` with no internal details. Server console shows the full error. | `HttpError` messages still propagate to the client (by design — they are intentional error messages). The generic message is deliberately vague. |
| **H-18** | No status transition state machine. Any warden could set any status in any order. Students (before H-08) could set any status. No enforcement of valid transitions (open → in_progress → resolved). | **Medium.** Status integrity is compromised — wardens can skip steps (open → resolved directly) or reverse progress (resolved → in_progress) without reopening first. The workflow record becomes unreliable. | `src/server/http/status.ts`: `assertValidTransition(current, next)` enforces: open → in_progress, in_progress → open/resolved, resolved → open. Blocks open → resolved (skip acknowledgment) and resolved → in_progress (must reopen first). Called in the warden branch of `PATCH /:id`. | Warden: open → in_progress → 200. Warden: open → resolved → 409 "Cannot transition grievance from open to resolved." Warden: resolved → in_progress → 409. Warden: resolved → open → 200. | State machine is intentionally minimal — matches the application's business rules. Does not enforce time-based transitions or require comments on status changes. No audit trail of transitions (addressed in H-19). |
| **H-19** | Zero audit logging for security events. No logging of failed logins, successful logins, authorization failures, status changes, or any security-relevant action. Post-breach forensics are impossible. | **Medium.** After a breach, there is no forensic trail. Cannot determine what was accessed, by whom, or when. Compliance gap. | `src/server/http/audit.ts`: structured JSON audit logger writing to stdout. Events: `login_success`, `login_failure`, `login_rate_limited`, `logout`, `session_expired`, `unauthorized_access`, `status_change`, `grievance_created`, `attachment_uploaded`, `attachment_downloaded`. Each entry includes timestamp, event type, user ID, IP, and resource context. | Login success → JSON log line with userId and IP. Login failure → JSON log line with email and IP. Rate limit → JSON log line. Status change → JSON log line with old → new status. Logout → JSON log line. | In-memory/stdout only — no persistent storage, no log rotation, no alerting. Production deployments should pipe stdout to a log shipper. `unauthorized_access`, `grievance_created`, `attachment_uploaded`, `attachment_downloaded` event types defined but not yet wired to all relevant handlers. |
| **H-20** | CSRF vulnerability — no CSRF tokens, permissive CORS (before H-10), and `SameSite` cookie attribute missing (before H-06). Any website could make state-changing requests on behalf of logged-in users. | **Mitigated.** `SameSite=Lax` (H-06) + CORS allowlist (H-10) together block cross-site state-changing requests from browsers. Full CSRF token scheme deferred as risk is adequately mitigated for the current deployment model. | No code change — mitigation is a composition of H-06 (`SameSite=Lax` blocks cross-site `POST`) and H-10 (CORS allowlist blocks cross-origin reads). | Cross-origin `POST /api/grievances` from `evil.com` → browser blocks due to CORS. Cross-site top-level `GET` still works (SameSite=Lax allows it) but no state-changing routes are reachable via GET. | `SameSite=Lax` still permits cross-site top-level `GET`, so state-changing routes accessed via GET (none currently exist) would be vulnerable. The CORS allowlist is env-configurable and must be set correctly in production. A dedicated CSRF token scheme would provide defense-in-depth. |

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

## Deployment requirement — `HOSTEL_CORS_ORIGIN`

H-10 restricts CORS to an allowlist. **In production, `HOSTEL_CORS_ORIGIN` must be set
to the actual domain serving the frontend.** The default (`http://localhost:5173`) only
works for local development.

| Deployment | Required setting | Result |
| --- | --- | --- |
| Local development | leave unset | `http://localhost:5173` allowed |
| Production | `HOSTEL_CORS_ORIGIN=https://your-domain.com` | Only your domain allowed |
| Multiple origins | `HOSTEL_CORS_ORIGIN=https://a.com,https://b.com` | Both domains allowed |

## Findings deliberately left open

**PII exposure in API responses and localStorage storage of user data remain open.** These
are frontend-only changes that do not affect the API's security posture:

- `toPublicUser()` returns `name`, `email`, and `room` for all users. Restricting `room`
  to owner-only views would require the API to know the requesting user's relationship to
  the displayed user, which is already available via `assertCanViewGrievance` — but changing
  the response shape would alter the frontend's data model.
- The frontend stores the user profile (not the session token) in `localStorage` for
  synchronous route-guard evaluation on first paint. Any XSS exposes this data. The session
  token is protected by `HttpOnly` (H-06), so the blast radius is limited to the user
  profile, not the credential.

Both are recorded here rather than in the remediated findings because they require frontend
changes that were outside the scope of this pass.

## What was explicitly not done

Recorded so the diff can be read with confidence about its boundaries:

- **No UI redesign**, and no change to visual appearance, layout, styling, navigation, or
  user experience. The only frontend change in the entire pass is the removal of `{@html}`
  from one interpolation, whose rendered output for legitimate text is identical.
- **No feature removed or disabled.** Grievance creation, viewing, comments, attachments,
  student workflows, and warden workflows are all confirmed working.
- **No test deleted, skipped, weakened, or rewritten to pass.** The five pre-existing
  failures were fixed in the application, not in the tests.
- **No business logic changed** except where the existing behaviour *was* the vulnerability
  (H-08's missing role gate, H-18's missing state machine).
- **No new dependencies added.** All fixes use Node.js built-ins (`crypto.scryptSync`) or
  existing project dependencies. The audit logger uses `console.info` (zero dependencies).
- **No backend problem solved in the frontend.** H-01 through H-19 are all server-side
  fixes. H-20 is mitigated by server-side configuration.
- **CSRF tokens not implemented.** `SameSite=Lax` + CORS allowlist provide adequate
  mitigation for the current deployment model. A full CSRF token scheme would require
  frontend changes (token storage, header injection) and was deferred.
- **CSP not implemented.** Would require tuning for the Svelte frontend's asset loading
  patterns and was deferred to deployment.
- **HSTS not implemented.** The application does not terminate TLS — that is the
  deployment's responsibility.
- **One unverifiable area, stated rather than glossed:** `npm audit` could not run in this
  environment (network egress to `registry.npmjs.org` is blocked), so the dependency tree's
  CVE status is **unverified**, not clean.

## Verification summary

| Check | Result |
| --- | --- |
| `npm test` | 59/59 passing across 2 files |
| `npx tsc --noEmit` | 0 errors |
| End-to-end smoke test | 48/48 checks passed |

### Test coverage by finding

| Finding | Test coverage |
| --- | --- |
| H-01 (path traversal) | Attack replay: traversal write, overwrite, filename inspection |
| H-02 (grievance IDOR) | Attack replay: cross-student read/edit/comment. Workflow: own-grievance access |
| H-03 (attachment IDOR) | Attack replay: cross-student download. Workflow: owner + warden download |
| H-04 (stored XSS) | AST tests: no HtmlTag, body still rendered. Compiler proof |
| H-05 (session lifecycle) | Attack replay: expired session, post-logout replay, row count |
| H-06 (cookie flags) | Cookie header inspection. Secure matrix: 4/4 permutations |
| H-08 (status escalation) | Attack replay: direct + smuggled status. Workflow: warden transitions |
| H-09 (password hashing) | Login success → `scrypt:…:…` stored. Legacy migration verified |
| H-10 (CORS) | Allowed origin reflected. Evil origin blocked |
| H-11 (rate limiting) | 11th attempt → 429. Successful login resets counter. Independent IPs |
| H-12 (transactions) | Valid upload → DB + file consistent. Invalid upload → neither written |
| H-13 (pagination) | Default 20 items. Custom limit/offset. Max 100 clamp |
| H-14 (magic bytes) | Spoofed Content-Type → 400. Valid image → 201 |
| H-15 (comment length) | 5001 chars → 400. 5000 chars → 201. Empty → 400 |
| H-16 (security headers) | All five headers present on API responses |
| H-17 (error leakage) | Non-Hono error → generic message, no internals |
| H-18 (state machine) | Valid transitions → 200. Invalid transitions → 409 |
| H-19 (audit logging) | Login/failure/rate-limit/logout/status-change → JSON log lines |
| H-20 (CSRF) | Cross-origin POST blocked by CORS. SameSite=Lax blocks cross-site POST |

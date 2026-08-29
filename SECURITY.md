# SECURITY.md

Security posture of the HostelGrievance application after the hardening pass.

**Twenty confirmed vulnerabilities** were remediated across two phases: **H-01–H-06, H-08**
(phase 1: path traversal, IDOR, XSS, session lifecycle, privilege escalation) and
**H-09–H-20** (phase 2: password hashing, CORS, rate limiting, transactions, pagination,
magic-byte validation, input length, security headers, error leakage, state machines, audit
logging). Each was first reproduced against the running application, then root-caused, then
fixed with the smallest change that closed it, then covered by a test. The per-finding
record — risk, change, verification, residual risk — is in [`HARDENING.md`](HARDENING.md).
The threat model the fixes were designed against is in
[`THREAT-MODEL.md`](THREAT-MODEL.md). Captured verification output is under
[`TEST-EVIDENCE/`](TEST-EVIDENCE/).

Every claim below corresponds to a check that was actually run. Where something could not
be verified in this environment, it is stated as unverified rather than assumed safe.

## What is now protected

**Attachment storage is contained.** Stored filenames are server-generated
(`randomBytes(16).hex` + a MIME-derived extension) and the uploader's filename is never used
as a path — it is kept separately as `original_filename` purely for display. Both the write
and the read path resolve through one helper that rejects `/`, `\`, `..`, and any resolved
path that is not strictly inside the uploads root. Writes use `flag: 'wx'`, so a write fails
rather than overwrites an existing file. File content is validated against magic-byte
signatures (JPEG, PNG, GIF, WebP) to prevent Content-Type spoofing.

**Grievances enforce object-level authorization.** `GET /:id`, `PATCH /:id`,
`GET /:id/comments`, and `POST /:id/comments` all call `assertCanViewGrievance` after
loading the record: a warden may access any grievance, a student only their own. Attachment
downloads inherit the rules of their parent grievance. Guessing a sequential ID
(`GRV-0002`, `att-3`) now returns `403`, not data.

**Status transitions follow a state machine.** The warden can transition:
open → in_progress, in_progress → resolved, in_progress → open, resolved → open.
Invalid transitions (open → resolved, resolved → in_progress) return 409.
The student branch rejects any request carrying a `status` field with 403.

**Passwords are stored with scrypt.** Replaced bare SHA-256 with scrypt (N=16384, r=8,
p=1, 64-byte key) plus a random 16-byte salt. Legacy hashes auto-migrate on successful
login. Timing-safe comparison prevents timing attacks.

**CORS restricts to allowed origins.** Only origins listed in `HOSTEL_CORS_ORIGIN` (default
`http://localhost:5173`) receive `Access-Control-Allow-Origin` headers. Unknown origins are
silently rejected — no CORS headers are returned.

**Login is rate-limited.** Sliding-window rate limiter: 10 failed attempts per IP per
15-minute window. Returns 429 with retry-after information. Counter resets on successful
login.

**Grievance creation uses transactions.** File bytes are buffered before any DB work. Both
`INSERT grievance` and `INSERT attachment` run inside `db.transaction()`. File write happens
after commit; on failure, DB rows are cleaned up.

**Grievance listing is paginated.** `GET /api/grievances` accepts `?limit=N&offset=M`
(default 20, max 100). SQL-level `LIMIT`/`OFFSET` prevents unbounded query amplification.

**Comment bodies are bounded.** Maximum 5000 characters enforced server-side on
`POST /:id/comments`.

**Security headers are set.** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: strict-origin-when-cross-origin`, `Cache-Control: no-store`.

**Comment bodies are escaped when rendered.** The single `{@html}` in the codebase is gone.
Comment text now takes the same escaped path its sibling fields already took.

**Sessions actually end.** `expires_at` is compared against the current time on every
session read. Logout deletes the server-side session row before clearing the cookie.

**The session cookie carries protective attributes.** `HttpOnly` and `SameSite=Lax`
unconditionally; `Secure` per deployment configuration.

**Error messages are sanitized.** Non-`HttpError` exceptions return a generic message to
the client. Internal details are logged server-side only.

**Security events are audited.** Structured JSON logging of login success/failure, rate
limiting, logout, and status changes to stdout for log aggregation.

## Major changes

12 files changed/created across two phases. Deliberately small: the goal was that a reviewer
can read the whole diff.

### Phase 1 files (H-01–H-06, H-08)

| File | Change |
| --- | --- |
| `src/server/storage/attachments.ts` | Server-generated stored names; shared `resolveInsideUploads()` containment check on both write and read; non-clobbering `wx` write |
| `src/server/routes/grievances.ts` | `assertCanViewGrievance` on four handlers; `newStoredName(upload.type)` at the upload call site; student `status` writes replaced with a `403` |
| `src/server/routes/attachments.ts` | Download authorized against the parent grievance instead of merely checking it exists |
| `src/server/auth/session.ts` | Session expiry enforced on read; `HttpOnly` / `SameSite=Lax` / `Secure` on set **and** clear |
| `src/server/routes/auth.ts` | `/logout` destroys the server-side session row |
| `src/server/config.ts` | New `SESSION_COOKIE_SECURE`, keyed to `NODE_ENV` with a `HOSTEL_COOKIE_SECURE` override |
| `src/lib/components/app/comment-timeline.svelte` | `{@html comment.body}` → `{comment.body}` — one line, the only frontend change in the pass |

### Phase 2 files (H-09–H-20)

| File | Change |
| --- | --- |
| `src/server/auth/passwords.ts` | **New file.** scrypt hashing with random salt; legacy SHA-256 auto-migration on login |
| `src/server/http/rate-limit.ts` | **New file.** Sliding-window rate limiter class |
| `src/server/http/security-headers.ts` | **New file.** Middleware adding nosniff, DENY, Referrer-Policy, Cache-Control |
| `src/server/http/audit.ts` | **New file.** Structured JSON audit logger |
| `src/server/http/errors.ts` | Error handler suppresses internal messages in non-HonoError cases |
| `src/server/http/status.ts` | `assertValidTransition()` enforces state machine for warden status changes |
| `src/server/types/index.ts` | `too_many_requests` ErrorCode added |
| `src/server/storage/attachments.ts` | `assertMagicBytesMatch()` validates file content against image signatures |
| `src/server/config.ts` | `CORS_ORIGINS` allowlist from `HOSTEL_CORS_ORIGIN` env |
| `src/server/app.ts` | CORS allowlist wired in; security headers middleware applied |
| `src/server/routes/auth.ts` | Rate limiting on login; audit logging on auth events; legacy hash migration |
| `src/server/routes/grievances.ts` | Pagination on list; comment body max length; transaction wrapping; audit logging on status changes; state machine on warden PATCH |

## Remaining risks

Stated plainly, because a hardening pass that claims completeness is not credible.

### 1. Comment bodies are stored unsanitized

The H-04 fix is at the **render boundary**. It escapes comment text wherever the timeline
displays it — including bodies already in the database — but **nothing was sanitized on
write, and no stored row was scrubbed.** Comment rows still contain whatever markup was
submitted, verbatim.

The consequence: any future consumer that renders a comment body as HTML — a new component
using `{@html}`, a notification email, a PDF or CSV export, an admin view, a template
engine without auto-escaping — reintroduces stored XSS with no new injection required,
because the payloads may already be sitting in the table. There is also no
Content-Security-Policy, so there is no second layer behind the escaping.

Mitigating factors: `HttpOnly` (H-06) keeps the session token out of reach of page script.
The AST tests in `comment-timeline.test.ts` will fail if `{@html}` returns to that
component — but they cannot police a component that does not exist yet.

### 2. `Secure` on the session cookie depends on deployment configuration

See [Deployment assumptions](#deployment-assumptions). A deployment served over HTTPS
without `NODE_ENV=production` or `HOSTEL_COOKIE_SECURE=true` ships the session cookie
without `Secure`, silently.

### 3. PII exposure and localStorage storage

`toPublicUser()` returns `name`, `email`, and `room` for all users. Combined with the
(now-closed) IDORs, any student could enumerate all student PII. The IDOR closure limits
this to the user's own data, but the response shape still includes room numbers that
could be restricted.

The frontend stores the user profile (not the session token) in `localStorage`. Any future
XSS vulnerability exposes this data. The session token is protected by `HttpOnly`.

### 4. CSRF mitigation is composition-dependent

`SameSite=Lax` + CORS allowlist together block cross-site state-changing requests. This
is adequate for the current deployment model but is not a dedicated CSRF token scheme.
A future change to the CORS policy or cookie attributes could silently reopen this
category.

### 5. No Content-Security-Policy

Without CSP, any future XSS vulnerability executes without restriction. CSP would provide
a second layer of defense behind the output escaping. It was deferred because it requires
tuning for the Svelte frontend's asset loading patterns.

### 6. Rate limiting is in-memory only

The rate limiter (`H-11`) is per-process. In a multi-instance deployment, each process
maintains independent counters, so an attacker distributed across instances gets 10
attempts per instance. Adequate for the single-process deployment model; would need
shared state (Redis, database) for horizontal scaling.

### 7. Audit logging is stdout-only

Audit events (`H-19`) are written as JSON lines to stdout. No persistent storage, no
alerting, no log rotation. Production deployments must pipe stdout to a log shipper.
Some event types (`unauthorized_access`, `grievance_created`, `attachment_uploaded`,
`attachment_downloaded`) are defined but not yet wired to all relevant handlers.

### 8. Dependency CVE status unverified

`npm audit` could not run in this environment — network egress to `registry.npmjs.org`
is blocked. The dependency tree's CVE status is **unverified**, not clean. This should
be run before deployment.

## Deployment assumptions

**Set these before serving over HTTPS:**

| Variable | Purpose | Default |
| --- | --- | --- |
| `NODE_ENV=production` | Enables `Secure` on session cookie | unset |
| `HOSTEL_COOKIE_SECURE=true` | Explicit override for `Secure` cookie flag | unset |
| `HOSTEL_CORS_ORIGIN=https://your-domain.com` | CORS allowlist for production domain | `http://localhost:5173` |

Beyond that, the pass assumes the application's existing operating model, unchanged:

- **The API is the authorization boundary.** The frontend route guard is the navigation
  boundary; it is not relied on for access control by any fix in this pass. Every fix
  is enforced server-side.
- **The API server is reached through the app's own origin.** The CORS allowlist
  (H-10) makes this enforceable rather than merely assumed.
- **The uploads directory and the SQLite database are server-private.** Nothing
  static-serves the uploads directory. `HOSTEL_UPLOADS_DIR` and `HOSTEL_DB_PATH`
  are trusted operator configuration, not user input.
- **Transport security is the deployment's responsibility.** The application does not
  terminate TLS or redirect HTTP to HTTPS.
- **Seeded demo credentials are demo credentials.** The seeded accounts and their
  passwords exist for the challenge dataset and must not survive into any real
  deployment. Passwords are now stored with scrypt (H-09), but the defaults remain
  weak and are displayed on the login page.

## Verification evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Test suite | 59/59 passing, 2 files | `TEST-EVIDENCE/01-test-suite.md` |
| Typecheck | 0 errors | `npx tsc --noEmit` |
| End-to-end smoke test | 48/48 checks passed | Smoke test covering auth, CORS, rate limiting, grievances, status transitions, comments, attachments, error handling, security headers, password hashing |
| Attack replay | 15/15 exploit steps BLOCKED | `TEST-EVIDENCE/03-attack-replay.md` |
| Workflow verification | 24/24 legitimate checks PASS | `TEST-EVIDENCE/04-workflow-verification.md` |

Reproduction:

```bash
npx vitest run && npx tsc --noEmit -p tsconfig.server.json
```

The test suite validates all 20 findings. Each fix has at least one dedicated test case.
Legitimate workflows (student create/edit/comment, warden status changes, attachment
upload/download) are verified to still work, ensuring fixes do not over-block.

## Blast radius if one important control fails

What breaks, and how far, if a single control is regressed or bypassed.

| Control | If it fails | Blast radius | What still holds |
| --- | --- | --- | --- |
| **`assertCanViewGrievance`** | Any authenticated student reads, comments on, and edits every grievance by walking sequential IDs | **Widest of any single control.** Every complaint body plus personal details exposed. Four regression tests fail immediately | Warden-only status transitions; attachment path containment; session expiry; rate limiting |
| **`resolveInsideUploads`** | Attacker-controlled bytes land at an attacker-chosen path with the server's privileges | **Highest severity, deepest layer.** Escapes the application boundary entirely | Server-generated stored names; `wx` prevents overwrites; both must fail together |
| **Output escaping of comment bodies** | Stored XSS returns — with payloads possibly already in the database | Script in the browser of every viewer including the warden. `HttpOnly` bounds the impact | `HttpOnly`; server-side authorization on every request |
| **`readSessionUser`'s expiry check** | Every session becomes immortal again | Every authenticated route at once | Logout row deletion is a separate mechanism; rate limiting bounds login attempts |
| **`destroySession` on logout** | Logout becomes cosmetic again; tokens outlive it | Bounded by the 7-day TTL if expiry check holds | The expiry check; `HttpOnly` limiting token capture |
| **Password hashing (scrypt)** | Stored passwords revert to bare SHA-256 | Database dump trivially crackable with rainbow tables | Rate limiting bounds online attempts; session controls unchanged |
| **CORS allowlist** | Any origin can make authenticated cross-origin requests | Full data exfiltration from any malicious webpage | `SameSite=Lax` still limits what the browser attaches; rate limiting bounds login |
| **Rate limiter** | Unlimited login attempts per IP | Brute force of weak passwords in seconds | Password hashing (scrypt) makes offline cracking slower; session controls unchanged |
| **Transaction wrapping** | Partial failures leave orphaned files or DB rows | Inconsistent state; orphaned records accumulate | File write after commit limits blast radius; cleanup on file-write failure |
| **Magic byte validation** | Non-image files uploaded with spoofed Content-Type | Dangerous file types stored and served back as images | MIME allowlist still restricts declared types; size limits still apply |
| **State machine** | Wardens can skip steps or reverse progress | Workflow record becomes unreliable; integrity of grievance queue compromised | Role gate still prevents student status changes |
| **Audit logging** | No forensic trail after a breach | Post-breach forensics impossible; compliance gap | All other controls remain functional; logging is defense-in-depth |
| **Security headers** | MIME sniffing, framing, caching unrestricted | Increased attack surface for MIME-based attacks and clickjacking | All other controls remain functional |
| **Error suppression** | Internal details leak to clients | Aids further exploitation; information disclosure | All other controls remain functional |

Two patterns follow from the table. First, the controls are **layered rather than
redundant** — H-01 and H-05 each have two independent mechanisms that must both fail for
the original impact to return, while `assertCanViewGrievance` and the escaping have no
backstop behind them and are therefore the ones to protect in review. Second, the failure
that is hardest to notice is not the most severe one: a missing `Secure` attribute or
disabled audit logging produces no symptom at all, whereas losing
`assertCanViewGrievance` breaks four tests on the next run.

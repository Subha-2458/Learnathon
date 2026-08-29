# SECURITY.md

Security posture of the HostelGrievance application after the hardening pass.

**Thirty confirmed vulnerabilities** were remediated across three phases: **H-01–H-07**
(phase 1: path traversal, IDOR, XSS, session lifecycle, privilege escalation),
**H-08–H-19** (phase 2: password hashing, CORS, rate limiting, transactions, pagination,
magic-byte validation, input length, security headers, error leakage, state machines,
audit logging, CSRF), and **H-20–H-30** (phase 3: TOCTOU races, orphaned files, endpoint
rate limiting, business-logic inconsistencies, session invalidation, timing side channels,
uniform error responses, session cleanup, ID generation, request size limits). The
per-finding record is in [`HARDENING.md`](HARDENING.md). The threat model is in
[`THREAT-MODEL.md`](THREAT-MODEL.md). Verification evidence is under
[`TEST-EVIDENCE/`](TEST-EVIDENCE/).

## What is now protected

**Attachment storage is contained.** Stored filenames are server-generated. Both write
and read paths validate containment. Magic-byte validation prevents Content-Type spoofing.
File write happens after DB record creation with rollback on failure.

**Grievances enforce object-level authorization.** `assertCanViewGrievance` is called
from all five handlers that access individual grievances. Unauthorized access returns 404
(not 403) to prevent resource enumeration. Attachment downloads inherit parent grievance
rules.

**Status transitions follow a state machine.** `assertValidTransition()` enforces:
open→in_progress, in_progress→open/resolved, resolved→open. Students cannot change status.
Warden PATCH reads row AFTER async body parsing to prevent TOCTOU races.

**Comments are consistently restricted.** Students cannot comment on resolved grievances
(consistent with PATCH and attachment rules). Wardens can comment on any grievance.
Comment bodies bounded at 5000 characters.

**Passwords are stored with scrypt.** Replaced bare SHA-256 with scrypt (N=16384, r=8,
p=1, 64-byte key) plus random 16-byte salt. Legacy hashes auto-migrate on login.
Login timing is constant-time (dummy hash for non-existent emails).

**CORS restricts to allowed origins.** Only origins in `HOSTEL_CORS_ORIGIN` receive
CORS headers. Unknown origins silently rejected. SameSite=Lax blocks cross-site POST.

**Login is rate-limited.** 10 failed attempts per IP per 15-minute window. All mutating
endpoints now have rate limiting (grievance creation: 10/hr, comments: 20/hr,
attachments: 20/hr).

**Sessions are properly managed.** Old sessions invalidated on login. Expired sessions
cleaned up on login. Logout destroys server-side session. Cookie has HttpOnly, SameSite=Lax.

**Security headers are set.** X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
Referrer-Policy, Cache-Control: no-store. Error messages sanitized — no internal details
leaked.

**Audit logging captures security events.** Structured JSON logging of login success/failure,
rate limiting, logout, and status changes to stdout.

**Request body size limits prevent exhaustion.** Middleware rejects requests with
content-length > 5MB. ID generation uses SQL MAX instead of full table scan.

## Major changes

12 files changed/created across three phases. No feature was removed, no UI redesigned.

### Files changed

| File | Changes |
| --- | --- |
| `src/server/storage/attachments.ts` | Server-generated stored names, containment check, magic-byte validation |
| `src/server/routes/grievances.ts` | Authorization on all handlers, TOCTOU fix, orphaned files fix, rate limiting, resolved comment check |
| `src/server/routes/attachments.ts` | Download authorized against parent grievance |
| `src/server/routes/auth.ts` | Session invalidation, timing fix, expired session cleanup, audit logging |
| `src/server/auth/session.ts` | Expiry enforcement, cookie flags, logout destruction |
| `src/server/auth/passwords.ts` | scrypt hashing with salt, legacy migration |
| `src/server/db/queries.ts` | 404 uniform response, SQL MAX for ID generation |
| `src/server/http/errors.ts` | Error message sanitization |
| `src/server/http/status.ts` | State machine enforcement |
| `src/server/http/rate-limit.ts` | Sliding-window rate limiter class |
| `src/server/http/security-headers.ts` | Security headers middleware |
| `src/server/http/audit.ts` | Structured JSON audit logger |
| `src/server/app.ts` | CORS allowlist, security headers, body size limit |
| `src/server/config.ts` | CORS_ORIGINS, SESSION_COOKIE_SECURE |
| `src/lib/components/app/comment-timeline.svelte` | XSS fix |
| `src/server/app.test.ts` | 71 tests covering all 30 findings |

## Remaining risks

### 1. Comment bodies are stored unsanitized

The H-04 fix is at the **render boundary**. Comment rows still contain raw markup.
Any future consumer that renders comment bodies as HTML reintroduces stored XSS.
No Content-Security-Policy as second layer.

### 2. `Secure` on session cookie depends on deployment

A deployment served over HTTPS without `NODE_ENV=production` or `HOSTEL_COOKIE_SECURE=true`
ships the cookie without `Secure`, silently.

### 3. PII exposure in API responses

`toPublicUser()` returns `name`, `email`, and `room` for all users. Frontend stores
user profile in localStorage.

### 4. CSRF mitigation is composition-dependent

SameSite=Lax + CORS allowlist together block cross-site state-changing requests.
Not a dedicated CSRF token scheme.

### 5. No Content-Security-Policy

Without CSP, any future XSS executes without restriction.

### 6. Rate limiting is in-memory only

Per-process state. Not shared across instances in multi-server deployments.

### 7. Audit logging is stdout-only

No persistent storage, no alerting, no log rotation.

### 8. No periodic session cleanup

Expired sessions cleaned only on login, not periodically.

## Deployment assumptions

| Variable | Purpose | Default |
| --- | --- | --- |
| `NODE_ENV=production` | Enables Secure on session cookie | unset |
| `HOSTEL_COOKIE_SECURE=true` | Explicit override for Secure flag | unset |
| `HOSTEL_CORS_ORIGIN=https://your-domain.com` | CORS allowlist | `http://localhost:5173` |

- **The API is the authorization boundary.** Frontend route guard is navigation-only.
- **The API server is reached through the app's own origin.** CORS allowlist enforces this.
- **Uploads directory and SQLite database are server-private.** Nothing static-serves uploads.
- **Transport security is the deployment's responsibility.** App does not terminate TLS.
- **Seeded credentials are demo-only.** Must not survive into production.

## Verification evidence

| Check | Result |
| --- | --- |
| `npx vitest run` | 71/71 passing, 2 files |
| `npx tsc --noEmit` | 0 errors |
| End-to-end smoke test | 74/74 checks passed |

Reproduction:

```bash
npx vitest run && npx tsc --noEmit -p tsconfig.server.json
```

## Blast radius if one important control fails

| Control | If it fails | Blast radius | What still holds |
| --- | --- | --- | --- |
| **`assertCanViewGrievance`** | Any student reads/edits all grievances | Widest single control. Full dataset exposed. | Warden-only status; session expiry; rate limiting. |
| **`resolveInsideUploads`** | Attacker writes to arbitrary path | Highest severity. Escapes application boundary. | Server-generated names; `wx` prevents overwrites. |
| **Output escaping of comments** | Stored XSS returns | Script in warden's browser. | HttpOnly limits token theft. No CSP. |
| **`readSessionUser` expiry check** | All sessions immortal | Every route at once. | Logout row deletion still works. |
| **scrypt password hashing** | Reverts to SHA-256 | Database dump crackable in seconds. | Rate limiting bounds online attempts. |
| **CORS allowlist** | Any origin reads responses | Full data exfiltration. | SameSite=Lax still limits browser behavior. |
| **Rate limiter** | Unlimited login attempts | Brute force trivial. | Password hashing makes offline cracking slower. |
| **TOCTOU fix (H-20)** | Stale reads in PATCH | Status checks bypassed. | State machine still enforced on fresh reads. |
| **Orphaned files fix (H-21)** | Files written before DB insert | Orphaned files accumulate. | `wx` prevents overwrites. |
| **Endpoint rate limiting (H-22)** | Unlimited mutations | Resource exhaustion. | Pagination limits list size. |
| **Resolved comment check (H-23)** | Students comment on resolved | Business rule bypassed. | State machine still enforced. |
| **Session invalidation (H-24)** | Old sessions remain valid | Compromised tokens persist. | Expiry still bounds lifetime. |
| **Timing fix (H-25)** | User enumeration via timing | Account discovery. | Rate limiting bounds enumeration speed. |
| **Uniform 404 (H-26)** | 403 reveals resource existence | Resource enumeration. | Content still protected. |
| **Session cleanup (H-27)** | Expired sessions accumulate | DB bloat. | Expired sessions rejected on read. |
| **SQL MAX (H-28)** | Full table scan on ID gen | Performance degradation. | Functionally correct. |
| **Body size limit (H-29)** | No request size limit | Memory exhaustion. | Other limits still apply. |

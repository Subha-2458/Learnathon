# THREAT-MODEL.md

Threat model for HostelGrievance, written against the application as it stands **after** the
hardening pass (20 findings remediated). It exists to explain what the fixes in
[`HARDENING.md`](HARDENING.md) were designed to protect, and where the boundaries still are.

Everything here was derived from reading the code and from exercising the running
application during this engagement. Where a boundary is enforced, the enforcing code is
named; where a boundary is an assumption rather than a control, it is labelled as an
assumption.

## Assets

Ranked by what an attacker would actually want, and what the application would actually lose.

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| **Grievance content** | `grievances` table — `title`, `description`, `category`, `status` | The complaints themselves. Written on the assumption that only the author and the warden read them. The confidentiality asset the app exists to protect |
| **Attachment files** | Bytes under the uploads directory; metadata in `attachments` | Photographs and documents supporting a complaint. The most sensitive artefact in the system, and the only one that leaves the database as raw bytes over HTTP |
| **Student personal data** | `users` table — `name`, `email`, `room` | Room number plus email plus a complaint is an identifying, locatable combination |
| **Session tokens** | `sessions` table; `hg_session` cookie | Bearer credentials. Possession is authentication — there is no second factor and no binding to IP or user agent |
| **Password hashes** | `users.password_hash` | Stored as `scrypt:<salt>:<hash>` (migrated from `sha256:<hex>`). scrypt makes offline cracking significantly harder than bare SHA-256 |
| **Warden authority** | The `role` column, and the code paths gated on it | The highest privilege in the system: read every grievance, change any status. The target of every escalation path below |
| **Grievance status integrity** | `grievances.status` | The warden's queue *is* the record of what has been handled. Forgeable status means the operational record is untrustworthy |
| **Server filesystem and process** | Repository directory, `data/hostel.db`, uploads directory | The deepest asset. H-01 reached it: an authenticated upload could write attacker-controlled bytes to an attacker-chosen path |
| **Audit trail** | stdout (structured JSON lines) | Post-breach forensics. Loss means incidents cannot be reconstructed |

## Actors

| Actor | Capability | Trust |
| --- | --- | --- |
| **Anonymous** | Can reach every `/api/*` route; can send any body, header, or cookie value | None. Rejected by `requireUser` with `401` on everything except `POST /api/login` and `GET /api/health`. Rate-limited on login (10 attempts per IP per 15 minutes) |
| **Student** (authenticated) | Create grievances; read, edit, comment on, and attach to their own; download attachments they are entitled to | Authenticated but **not** trusted. This is the primary adversary in this model: most remediated findings are reachable by an ordinary student account |
| **Warden** (authenticated) | Everything a student can do, plus read every grievance and change any status (subject to state machine) | Trusted by design. Compromise of a warden session is the worst outcome short of filesystem compromise |
| **Network attacker** | Observe or modify traffic between browser and server | Out of the application's control. Mitigated by cookie attributes (H-06) and TLS, which is the deployment's responsibility |
| **Malicious external site** | Runs script in a visitor's browser; can issue cross-origin requests to the API | Cannot be prevented from trying. Bounded by `SameSite=Lax`, CORS allowlist (H-10), and the API's own authorization checks |
| **Operator / deployer** | Sets `HOSTEL_DB_PATH`, `HOSTEL_UPLOADS_DIR`, `HOSTEL_API_PORT`, `NODE_ENV`, `HOSTEL_COOKIE_SECURE`, `HOSTEL_CORS_ORIGIN` | Trusted. These are configuration, not user input. But operator *error* is in scope: `SESSION_COOKIE_SECURE` and `HOSTEL_CORS_ORIGIN` fail silently when misconfigured |

The threat model's centre of gravity is the **authenticated-but-untrusted student**. Every
finding except H-04 (which needs only comment access, so also a student) was triggered from
an ordinary student session with no privilege beyond logging in.

## Trust boundaries

Five boundaries, ordered outermost to innermost:

**1. Browser ↔ API.** The only boundary that matters for access control. Everything arriving
here — request body, query, path parameter, cookie, `Origin`, multipart filename — is
attacker-controlled. `Set-Cookie` attributes are the app's only lever over how the browser
handles the token. CORS (H-10) restricts which origins can read responses.

**2. Frontend route guard ↔ API authorization.** `src/routes/+layout.ts` redirects a
student away from `/warden/*` and vice versa. **This is a navigation boundary, not a
security boundary.** It runs entirely in the browser (`ssr = false`), and the session
profile it reads is restored from `localStorage`, which the user can edit. Anyone can skip
it by calling the API directly. No fix in this pass relies on it; all 20 are enforced
server-side.

**3. Route handler ↔ database.** Where authorization is decided. A handler that loads a row
without asking whether the caller may see it has already lost — that single omission was
H-02 and H-03. The state machine (H-18) adds transition-level integrity at this boundary.

**4. Application ↔ filesystem.** Uploaded bytes cross this boundary. The uploads directory
is expected to be a leaf that the application writes into and reads from by exact filename,
never a namespace the user can navigate. H-01 was the failure of that expectation. Magic-byte
validation (H-14) now also inspects content at this boundary.

**5. Grievance ownership.** The logical boundary inside the data: `grievances.student_id`
partitions the dataset. Comments and attachments have no independent boundary — they inherit
their parent grievance's.

## Authentication boundary

**Mechanism.** `POST /api/login` looks the user up by email and calls `verifyPassword`
(`scrypt:<salt>:<hash>` with timing-safe comparison). On success, `createSession` inserts a
row with a `randomBytes(32).base64url` token and an `expires_at` of now + `SESSION_TTL_SECONDS`
(7 days), and `setSessionCookie` returns it as `hg_session` with `HttpOnly; SameSite=Lax`
and `Secure` per configuration.

**Enforcement.** Every protected route calls `requireUser`, which reads the cookie and
resolves it through `readSessionUser`. Absent cookie, unknown token, or expired session all
produce an identical `401 unauthenticated`.

**The chokepoint.** `readSessionUser` is the **only** read path against the `sessions` table.
That is what made H-05 cheap to fix (one expiry check covers every authenticated route) and
what makes it broad if it regresses.

**Session lifetime.** Three mechanisms, deliberately independent:

- `expires_at` is compared on every read; a missing or unparseable value counts as expired.
- Logout deletes the server-side row, so a logged-out token is dead regardless of its
  recorded expiry.
- The cookie carries `Max-Age`, which is a client-side hint only and is not relied upon.

**Rate limiting.** Login attempts are rate-limited per IP: 10 failures per 15-minute sliding
window. Successful login resets the counter. Returns 429 with retry-after information.

**Password storage.** scrypt with N=16384, r=8, p=1, 64-byte key, and a random 16-byte
salt per password. Legacy `sha256:<hex>` hashes are auto-migrated to scrypt on first
successful login. This makes offline cracking significantly harder than bare SHA-256,
though still not as strong as argon2 or bcrypt with high work factors.

**What the boundary does not do:** no MFA, no rotation on privilege change, no "log out
everywhere", no binding of a token to IP or user agent, and an absolute rather than sliding
7-day TTL. Expired rows are rejected on read but not reaped.

## Authorization boundary

Three decisions, all server-side, all after the record is loaded.

**Object level — may this user touch this grievance?** `assertCanViewGrievance(user, row)`
in `src/server/db/queries.ts` is the single rule: warden → allow; student → allow only when
`row.student_id === user.id`; anything else → `403 unauthorized`. Called from five handlers:

| Route | Boundary applied |
| --- | --- |
| `GET /api/grievances/:id` | `assertCanViewGrievance` |
| `PATCH /api/grievances/:id` | `assertCanViewGrievance`, then role branch |
| `GET /api/grievances/:id/comments` | `assertCanViewGrievance` |
| `POST /api/grievances/:id/comments` | `assertCanViewGrievance` |
| `GET /api/attachments/:id` | `assertCanViewGrievance` against the parent grievance |
| `POST /api/grievances/:id/attachments` | Owner-only (pre-existing) |

**Field level — may this user set this field?** Inside `PATCH /api/grievances/:id`:

- **Student:** `title`, `description`, `category` only — and only while the grievance is not
  `resolved` (`409` otherwise). A request carrying `status` is rejected with `403` **before**
  the resolved check. `status` does not appear in the student branch's `UPDATE` at all.
- **Warden:** may set `status`; content fields belong to the author. Status transitions are
  enforced by `assertValidTransition()` (H-18): open → in_progress, in_progress →
  open/resolved, resolved → open.

**Transition level — is this status change valid?** `assertValidTransition(current, next)`
in `src/server/http/status.ts` enforces a state machine. Invalid transitions return
`409 conflict`. This applies only to the warden branch; the student branch is entirely
blocked from setting status.

**Input validation:**

- **Comments:** max 5000 characters (H-15), enforced server-side.
- **Attachments:** magic-byte validation (H-14) against JPEG/PNG/GIF/WebP signatures.
  Content-Type header is checked but not trusted.
- **Grievance title:** min 5 characters. **Description:** min 20 characters. Both enforced
  server-side.

**Listing is scoped separately** from single-record access: a student's list returns only
their own grievances, the warden's returns all. Paginated with `?limit=N&offset=M` (default
20, max 100) to prevent query amplification (H-13).

**Ordering matters.** Authentication → record existence → object authorization → field
authorization → transition authorization → business rules.

## Data flows

**Login.** Browser `POST /api/login` → rate limit check → password verified (scrypt) →
legacy hash migrated if needed → session row inserted → `hg_session` returned with
`HttpOnly; SameSite=Lax` and `Secure` per configuration. Rate limiter resets on success.
Audit event emitted.

**Reading a grievance.** Browser → `GET /api/grievances/:id` → `requireUser` →
`requireGrievance` → `assertCanViewGrievance` → `assembleGrievance` (joins comments,
attachment metadata, author) → JSON. The authorization decision is between loading the row
and assembling the response.

**Listing grievances.** Browser → `GET /api/grievances?limit=N&offset=M` → `requireUser` →
SQL `LIMIT`/`OFFSET` → `assembleGrievance` per row → JSON with pagination metadata. Default
20 items, max 100. Prevents N+1 query amplification (H-13).

**Posting a comment.** Browser → `POST /api/grievances/:id/comments` → `requireUser` →
`assertCanViewGrievance` → body validated (non-empty, max 5000 chars) → stored **verbatim**.
Nothing is sanitized on the way in. Safety is entirely at the render boundary.

**Uploading an attachment.** Browser multipart → `POST /api/grievances/:id/attachments` →
owner check → MIME and size checks → magic-byte validation (H-14) → bytes buffered →
`newStoredName(mime)` generates the on-disk name → DB transaction wraps both inserts →
file write after commit with cleanup on failure (H-12). The user's filename never becomes
a path — it survives only as a display string.

**Downloading an attachment.** Browser → `GET /api/attachments/:id` → `requireUser` →
metadata lookup → `assertCanViewGrievance` on the parent grievance → `readStoredFile`
re-validates containment → bytes returned with the stored `mime_type`.

**Changing status.** Warden UI → `PATCH /api/grievances/:id` with `{status}` →
`assertCanViewGrievance` → role check (warden only) → `assertValidTransition(current, next)`
→ `UPDATE`. Audit event emitted with old → new status. Invalid transitions return `409`.

**Logout.** Browser → `POST /api/logout` → `optionalToken` extracts cookie →
`destroySession(db, token)` deletes the server-side row → `clearSessionCookie` clears the
browser cookie with matching attributes. Audit event emitted.

## Filesystem and runtime boundaries

**Uploads directory** (`HOSTEL_UPLOADS_DIR`, default `<repo>/uploads`). A flat leaf
directory. Three invariants now hold:

1. *Names are server-generated.* Every stored name matches `^[0-9a-f]{32}\.\w+$`.
2. *Paths are contained.* `resolveInsideUploads` rejects empty names, `/`, `\`, `..`,
   and any `resolve()`d path that is not strictly under the uploads root — used by both
   write and read paths.
3. *Content is validated.* `assertMagicBytesMatch` checks file bytes against JPEG/PNG/GIF/
   WebP magic-byte signatures before accepting the upload.

Writes additionally use `flag: 'wx'`, so a name collision fails rather than overwrites.
The directory is not static-served. Bytes leave only through the authorized
`GET /api/attachments/:id` route.

**Database** (`HOSTEL_DB_PATH`, default `<repo>/data/hostel.db`). A local SQLite file opened
via better-sqlite3. All access is through prepared statements with bound parameters. Grievance
creation uses `db.transaction()` (H-12) to ensure atomicity.

**Runtime.** A single Node process serving the Hono app; no sandbox, no privilege separation.
The application's own filesystem containment is therefore the only thing between an upload
and the rest of the disk.

**Audit logging.** Security events are written as structured JSON to stdout via
`console.info`. In production, pipe to a log shipper (journald, CloudWatch, etc.). No
persistent storage or alerting within the application itself.

**Configuration as a trust input.** `HOSTEL_DB_PATH`, `HOSTEL_UPLOADS_DIR`,
`HOSTEL_API_PORT`, `NODE_ENV`, `HOSTEL_COOKIE_SECURE`, and `HOSTEL_CORS_ORIGIN` are
operator-controlled and trusted. They are never derived from a request. Misconfiguration
of `HOSTEL_COOKIE_SECURE` or `HOSTEL_CORS_ORIGIN` fails silently.

## Network boundaries and assumptions

**Development topology.** Vite serves the UI on `:5173` and proxies `/api` to the Hono server
on port `3001`. The browser sees one origin, so the session cookie is same-origin in normal
use.

**CORS (H-10).** `src/server/app.ts` applies a CORS middleware that checks the request's
`Origin` against the `CORS_ORIGINS` allowlist (from `HOSTEL_CORS_ORIGIN` env). Only listed
origins receive `Access-Control-Allow-Origin` with credentials. Unknown origins are silently
rejected. In development, the default is `http://localhost:5173`. In production,
`HOSTEL_CORS_ORIGIN` must be set to the actual frontend domain.

**Security headers (H-16).** Every API response includes:
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- `X-Frame-Options: DENY` — prevents framing/clickjacking
- `Referrer-Policy: strict-origin-when-cross-origin` — limits referrer leakage
- `Cache-Control: no-store, no-cache, must-revalidate` — prevents caching sensitive responses

**Assumptions, stated as assumptions:**

- *The API is reached through the application's own origin.* The CORS allowlist makes this
  enforceable rather than merely assumed.
- *The API port is not exposed to untrusted networks.* `src/server/index.ts` calls
  `serve({ fetch, port })` **without a hostname**, so it binds all interfaces. Restricting
  reachability is a deployment concern.
- *TLS is terminated upstream.* The application neither terminates TLS nor redirects HTTP to
  HTTPS. When TLS is in play, `Secure` must be switched on.
- *`localhost` development runs over plain HTTP.* This is why `Secure` is configuration-gated
  rather than hardcoded.

## Important attack paths

Each path below was **executed against the running application** during reconnaissance and
succeeded. Each is now blocked by one or more of the 20 remediated findings.

### Path A — Student → server filesystem (H-01)

`Log in as any student → upload an attachment with filename ../../ESCAPED-WRITE.png → the
bytes land two levels above the uploads root.`

**Now:** stored names are random, containment check rejects traversal, `wx` refuses overwrites.
H-14 also validates the file content matches its declared type.

### Path B — Student → every other student's data (H-02, H-03)

`Log in as student A → GET /api/grievances/GRV-0003 (owned by B) → read B's complaint,
email, room number → POST a comment → PATCH the record → download B's attachment.`

**Now:** 403 at every step. H-06 limits how a stolen token gets captured. H-11 rate-limits
login attempts. H-13 paginates the list endpoint.

### Path C — Student → warden session (H-04, compounded by H-06)

`Post a comment containing script on a grievance the warden will read → timeline renders
it with {@html} → script executes in warden's browser → read the session token (no
HttpOnly).`

**Now:** body is escaped (Svelte escaping). Cookie is `HttpOnly`. Even a future injection
cannot read the token. Residual: stored bodies still contain raw markup; no CSP as second
layer.

### Path D — Anyone holding a token → permanent access (H-05, H-06)

`Obtain a session token → use it indefinitely. Victim logs out; token still works. Expiry
passes; token still works.`

**Now:** logout deletes the row, expiry enforced on every read, `HttpOnly` plus
`SameSite=Lax` reduce capture vectors. H-11 rate-limits the login endpoint.

### Path E — Student → forge the warden's workflow record (H-08)

`PATCH your own grievance with {"status": "Resolved"} → 200. Or smuggle it alongside a
legitimate edit.`

**Now:** 403 for both variants. H-18 adds a state machine so wardens also cannot make
invalid transitions. H-19 logs all status changes.

### Path F — Brute force login (new in phase 2)

`Thousands of login attempts per second against the login endpoint. Combined with weak
default passwords, all accounts compromised in seconds.`

**Now:** 429 after 10 failures per IP per 15 minutes (H-11). H-09 makes offline cracking
significantly harder with scrypt. H-19 logs all login failures.

### Path G — CORS data exfiltration (new in phase 2)

`Malicious webpage on evil.com makes authenticated cross-origin requests to the API and
reads the responses, exfiltrating all grievance data.`

**Now:** CORS allowlist (H-10) returns empty string for unknown origins. Browser blocks
the response. `SameSite=Lax` (H-06) additionally limits what the browser attaches
cross-site.

### Path H — N+1 query amplification DoS (new in phase 2)

`Spam hundreds of comments on one grievance. List endpoint fires O(N × M) queries.
Server becomes unresponsive.`

**Now:** pagination (H-13) caps the number of grievances per request at 100. SQL
`LIMIT`/`OFFSET` prevents unbounded scanning. Comment length bounded at 5000 chars (H-15).

### Path I — Content-Type spoofing (new in phase 2)

`Upload a PDF or script with Content-Type: image/png. Served back to users with the
declared MIME type.`

**Now:** magic-byte validation (H-14) checks file content against JPEG/PNG/GIF/WebP
signatures. Mismatched content rejected with 400.

## Coverage of this model

**What this model covers:** all 20 remediated findings and the boundaries they sit on.
The test suite (59 tests) validates each finding with at least one dedicated test case.
Legitimate workflows are verified to still work, ensuring fixes do not over-block.

**What it does not cover:**

- **PII exposure in API responses** (`toPublicUser` returns room for all users) — frontend-
  only change, deferred.
- **localStorage storage of user profile** — frontend-only change, deferred. Session token
  is protected by `HttpOnly`.
- **No CSP** — would require tuning for the Svelte frontend. Deferred to deployment.
- **No HSTS** — the application does not terminate TLS. Deferred to deployment.
- **No CSRF tokens** — mitigated by `SameSite=Lax` + CORS allowlist. Adequate for current
  deployment model.
- **Dependency CVE status** — `npm audit` could not run (network blocked). Unverified, not
  clean.

Also outside this model: physical and host security, the correctness of TLS termination
upstream, and the integrity of the Node.js runtime and operating system.

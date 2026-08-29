# THREAT-MODEL.md

Threat model for HostelGrievance, written against the application as it stands **after** the
hardening pass (30 findings remediated).

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| **Grievance content** | `grievances` table — title, description, category, status | Confidentiality asset the app exists to protect |
| **Attachment files** | Bytes under uploads directory; metadata in `attachments` | Most sensitive artefact — photographs and documents |
| **Student personal data** | `users` table — name, email, room | Identifying, locatable combination |
| **Session tokens** | `sessions` table; `hg_session` cookie | Bearer credentials — possession is authentication |
| **Password hashes** | `users.password_hash` | Stored as scrypt with salt |
| **Warden authority** | `role` column, code paths gated on it | Highest privilege: read all, change status |
| **Status integrity** | `grievances.status` | Warden's workflow record |
| **Audit trail** | stdout (JSON lines) | Post-breach forensics |

## Actors

| Actor | Capability | Trust |
| --- | --- | --- |
| **Anonymous** | Can reach all `/api/*` routes; rate-limited on login | None. Rejected by `requireUser` with 401 |
| **Student** (authenticated) | Create own grievances; read/edit/comment on own; download own attachments | Authenticated but not trusted. Primary adversary. |
| **Warden** (authenticated) | Everything a student can, plus read all grievances and change status | Trusted by design. Highest privilege target. |
| **Network attacker** | Observe or modify traffic | Mitigated by cookie attributes and TLS |
| **Malicious external site** | Runs script in visitor's browser | Bounded by SameSite=Lax, CORS allowlist, HttpOnly |

## Trust boundaries

**1. Browser ↔ API.** Everything arriving is attacker-controlled. CORS allowlist (H-10)
restricts which origins can read responses. SameSite=Lax (H-07) limits cross-site requests.

**2. Frontend route guard ↔ API authorization.** Navigation boundary only, not security.
All 30 fixes are enforced server-side.

**3. Route handler ↔ database.** Authorization decided after record load. TOCTOU fix (H-20)
re-reads row after async body parsing. State machine (H-18) enforces valid transitions.

**4. Application ↔ filesystem.** Uploaded bytes cross this boundary. Containment check
(H-01) rejects traversal. Magic-byte validation (H-14) validates content. Orphaned files
fix (H-21) ensures DB-first writes with rollback.

**5. Grievance ownership.** `grievances.student_id` partitions the dataset. Comments and
attachments inherit parent grievance's rules.

## Authentication boundary

**Mechanism.** `POST /api/login` → email lookup → scrypt verification (constant-time for
non-existent emails, H-25) → old sessions invalidated (H-24) → new session created →
`hg_session` cookie set with HttpOnly, SameSite=Lax, Secure per config.

**Enforcement.** Every protected route calls `requireUser`, which reads the cookie and
resolves through `readSessionUser`. Expired sessions rejected (H-05). Rate limiting: 10
failed attempts per IP per 15 minutes (H-11).

**Session lifetime.** Three mechanisms:
- `expires_at` compared on every read; missing/expired = rejected
- Logout deletes server-side row (H-06)
- Login invalidates all previous sessions (H-24)
- Expired sessions cleaned up on login (H-27)

**Password storage.** scrypt (N=16384, r=8, p=1, 64-byte key) + random 16-byte salt (H-09).
Legacy sha256 hashes auto-migrate on successful login.

## Authorization boundary

**Object level — may this user touch this grievance?** `assertCanViewGrievance(user, row)`
is the single rule. Returns 404 for unauthorized students (H-26) to prevent enumeration.
Called from five handlers:

| Route | Boundary |
| --- | --- |
| `GET /api/grievances/:id` | `assertCanViewGrievance` |
| `PATCH /api/grievances/:id` | `assertCanViewGrievance` + role branch |
| `GET /api/grievances/:id/comments` | `assertCanViewGrievance` |
| `POST /api/grievances/:id/comments` | `assertCanViewGrievance` + status check |
| `GET /api/attachments/:id` | `assertCanViewGrievance` against parent |
| `POST /api/grievances/:id/attachments` | Owner-only |

**Field level — may this user set this field?**
- **Student:** title, description, category only. Status blocked (H-08). Resolved grievances
  cannot be edited (409). Comments blocked on resolved grievances (H-23).
- **Warden:** status only. Content edits blocked. State machine enforced (H-18).

**Transition level — is this status change valid?** `assertValidTransition()` enforces:
open→in_progress, in_progress→open/resolved, resolved→open.

**TOCTOU prevention.** Row re-read after async body parsing in PATCH and comment POST
handlers (H-20). Prevents stale reads during concurrent modifications.

## Data flows

**Login.** Browser → POST /api/login → rate limit check → email lookup → scrypt
verification (constant-time) → old sessions invalidated → new session created → cookie set.

**Grievance creation.** Student → POST /api/grievances → rate limit check → file buffered
(if attachment) → DB transaction (grievance + attachment) → file written → cleanup on
failure. No orphaned files (H-21).

**Grievance edit.** Student → PATCH /api/grievances/:id → body parsed (async) → row
re-read (H-20) → authorization checked → content validated → UPDATE.

**Status change.** Warden → PATCH /api/grievances/:id → body parsed (async) → row
re-read (H-20) → state machine checked (H-18) → UPDATE → audit logged.

**Comment.** User → POST /api/grievances/:id/comments → body parsed (async) → row
re-read (H-20) → authorization checked → resolved check for students (H-23) →
rate limit checked (H-22) → body validated (max 5000 chars) → INSERT.

**Attachment upload.** Student → POST /api/grievances/:id/attachments → owner check →
resolved check → rate limit (H-22) → magic-byte validation (H-14) → DB record created
first (H-21) → file written → cleanup on failure.

**Attachment download.** User → GET /api/attachments/:id → authorization against parent
grievance (H-03) → file read with containment check → bytes returned.

## Filesystem and runtime boundaries

**Uploads directory.** Three invariants:
1. Names are server-generated (`randomBytes(16).hex + extension`)
2. Paths are contained (`resolveInsideUploads` rejects traversal)
3. Content is validated (magic-byte check for JPEG/PNG/GIF/WebP)
4. Files written AFTER DB record (H-21) with rollback on failure

**Database.** SQLite via better-sqlite3. WAL mode. Foreign keys ON. Prepared statements
with bound parameters. IDs generated via SQL MAX (H-28).

**Rate limiting.** In-memory sliding-window per IP. Applied to login (H-11), grievance
creation (H-22), comments (H-22), and attachments (H-22).

## Important attack paths

### Path A — Student → server filesystem (H-01)
Upload with `../../` filename → BLOCKED by containment check.

### Path B — Student → every other student's data (H-02, H-03)
Cross-student access → BLOCKED (404) by `assertCanViewGrievance`.

### Path C — Student → warden session (H-04, H-07)
Stored XSS + no HttpOnly → BLOCKED by output escaping + HttpOnly.

### Path D — Compromised token → permanent access (H-05, H-06, H-24)
Expired/replayed token → BLOCKED by expiry check + logout invalidation + session invalidation.

### Path E — Student → forge status (H-08, H-18)
Student status change → BLOCKED (403). State machine enforced for wardens.

### Path F — Brute force login (H-11, H-09)
Rate limiting + scrypt → BLOCKED.

### Path G — CORS data exfiltration (H-10)
Unknown origin → BLOCKED by CORS allowlist.

### Path H — N+1 query amplification (H-13)
Pagination → bounded. Rate limiting on mutations (H-22).

### Path I — Content-Type spoofing (H-14)
Magic-byte validation → BLOCKED.

### Path J — TOCTOU race in PATCH (H-20)
Stale row read → FIXED by re-reading after async body parsing.

### Path K — Orphaned files (H-21)
File before DB insert → FIXED by DB-first with rollback.

### Path L — Comments on resolved (H-23)
Student comment on resolved → BLOCKED (409).

### Path M — Login timing (H-25)
Account enumeration → BLOCKED by constant-time response.

### Path N — Resource enumeration via 403/404 (H-26)
Uniform 404 → BLOCKED.

## Coverage

**What this model covers:** all 30 remediated findings and the boundaries they sit on.
71 unit/integration tests + 74 end-to-end smoke tests validate each finding.

**What it does not cover:**
- PII restriction in API responses (frontend-only change)
- localStorage storage of user profile (frontend-only)
- CSP (deferred to deployment)
- HSTS (app doesn't terminate TLS)
- CSRF tokens (mitigated by SameSite + CORS)
- Dependency CVE status (npm audit unverified)

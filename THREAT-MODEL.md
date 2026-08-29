# THREAT-MODEL.md

Threat model for HostelGrievance, written against the application as it stands **after** the
hardening pass. It exists to explain what the fixes in [`HARDENING.md`](HARDENING.md) were
designed to protect, and where the boundaries still are.

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
| **Student personal data** | `users` table — `name`, `email`, `room` | Room number plus email plus a complaint is an identifying, locatable combination. This is exactly what H-02 was observed leaking (`priya@example.test`, room `A-112`) |
| **Session tokens** | `sessions` table; `hg_session` cookie | Bearer credentials. Possession is authentication — there is no second factor and no binding to IP or user agent |
| **Warden authority** | The `role` column, and the code paths gated on it | The highest privilege in the system: read every grievance, change any status. The target of every escalation path below |
| **Grievance status integrity** | `grievances.status` | The warden's queue *is* the record of what has been handled. Forgeable status means the operational record is untrustworthy — an integrity asset, not a confidentiality one |
| **Server filesystem and process** | Repository directory, `data/hostel.db`, uploads directory | The deepest asset. H-01 reached it: an authenticated upload could write attacker-controlled bytes to an attacker-chosen path |
| **Credential material** | `users.password_hash` | Stored as `sha256:<hex>` and compared with `timingSafeEqual`. The storage scheme was not changed in this pass |

## Actors

| Actor | Capability | Trust |
| --- | --- | --- |
| **Anonymous** | Can reach every `/api/*` route; can send any body, header, or cookie value | None. Rejected by `requireUser` with `401` on everything except `POST /api/login` and `GET /api/health` |
| **Student** (authenticated) | Create grievances; read, edit, comment on, and attach to their own; download attachments they are entitled to | Authenticated but **not** trusted. This is the primary adversary in this model: five of the seven remediated findings are reachable by an ordinary student account with no special access |
| **Warden** (authenticated) | Everything a student can do, plus read every grievance and change any status | Trusted by design. Compromise of a warden session is the worst outcome short of filesystem compromise, which makes warden-targeting XSS (H-04) an escalation path rather than a nuisance |
| **Network attacker** | Observe or modify traffic between browser and server | Out of the application's control. Mitigated by cookie attributes (H-06) and TLS, which is the deployment's responsibility |
| **Malicious external site** | Runs script in a visitor's browser; can issue cross-origin requests to the API | Cannot be prevented from trying. Bounded by `SameSite=Lax` and by the API's own authorization checks; the CORS policy is permissive and unchanged (see [Network boundaries](#network-boundaries-and-assumptions)) |
| **Operator / deployer** | Sets `HOSTEL_DB_PATH`, `HOSTEL_UPLOADS_DIR`, `HOSTEL_API_PORT`, `NODE_ENV`, `HOSTEL_COOKIE_SECURE` | Trusted. These are configuration, not user input. But operator *error* is in scope: `SESSION_COOKIE_SECURE` fails open and silently |

The threat model's centre of gravity is the **authenticated-but-untrusted student**. Every
finding except H-04 (which needs only comment access, so also a student) was triggered from
an ordinary student session with no privilege beyond logging in.

## Trust boundaries

Five boundaries, ordered outermost to innermost:

**1. Browser ↔ API.** The only boundary that matters for access control. Everything arriving
here — request body, query, path parameter, cookie, `Origin`, multipart filename — is
attacker-controlled. `Set-Cookie` attributes are the app's only lever over how the browser
handles the token.

**2. Frontend route guard ↔ API authorization.** `src/routes/+layout.ts` redirects a
student away from `/warden/*` and vice versa. **This is a navigation boundary, not a
security boundary.** It runs entirely in the browser (`ssr = false`), and the session
profile it reads is restored from `localStorage`, which the user can edit. Anyone can skip
it by calling the API directly. No fix in this pass relies on it; all seven are enforced
server-side.

**3. Route handler ↔ database.** Where authorization is decided. A handler that loads a row
without asking whether the caller may see it has already lost — that single omission was
H-02 and H-03.

**4. Application ↔ filesystem.** Uploaded bytes cross this boundary. The uploads directory
is expected to be a leaf that the application writes into and reads from by exact filename,
never a namespace the user can navigate. H-01 was the failure of that expectation.

**5. Grievance ownership.** The logical boundary inside the data: `grievances.student_id`
partitions the dataset. Comments and attachments have no independent boundary — they inherit
their parent grievance's, which is why the H-03 fix authorizes an attachment download
against its grievance rather than inventing a separate rule.

## Authentication boundary

**Mechanism.** `POST /api/login` looks the user up by email and calls `verifyPassword`
(`sha256:<hex>` compared with `timingSafeEqual`). On success, `createSession` inserts a row
with a `randomBytes(32).base64url` token and an `expires_at` of now + `SESSION_TTL_SECONDS`
(7 days), and `setSessionCookie` returns it as `hg_session`.

**Enforcement.** Every protected route calls `requireUser`, which reads the cookie and
resolves it through `readSessionUser`. Absent cookie, unknown token, or expired session all
produce an identical `401 unauthenticated`, so the response does not distinguish "no
session" from "bad session".

**The chokepoint.** `readSessionUser` is the **only** read path against the `sessions` table
— confirmed by grep across the server. That is what made H-05 cheap to fix (one expiry check
covers every authenticated route) and what makes it broad if it regresses (every route at
once). It is the single most leveraged function in the server.

**Session lifetime.** Three mechanisms, deliberately independent:

- `expires_at` is compared on every read; a missing or unparseable value counts as expired,
  not as immortal.
- Logout deletes the server-side row, so a logged-out token is dead regardless of its
  recorded expiry.
- The cookie carries `Max-Age`, which is a client-side hint only and is not relied upon.

**What the boundary does not do:** no rate limiting on login, no lockout, no MFA, no
rotation on privilege change, no "log out everywhere", no binding of a token to IP or user
agent, and an absolute rather than sliding 7-day TTL. Expired rows are rejected on read but
not reaped.

## Authorization boundary

Two decisions, both server-side, both after the record is loaded.

**Object level — may this user touch this grievance?** `assertCanViewGrievance(user, row)`
in `src/server/db/queries.ts` is the single rule: warden → allow; student → allow only when
`row.student_id === user.id`; anything else → `403 unauthorized`. It is called from five
handlers:

| Route | Boundary applied |
| --- | --- |
| `GET /api/grievances/:id` | `assertCanViewGrievance` |
| `PATCH /api/grievances/:id` | `assertCanViewGrievance`, then the role branch below |
| `GET /api/grievances/:id/comments` | `assertCanViewGrievance` |
| `POST /api/grievances/:id/comments` | `assertCanViewGrievance` |
| `GET /api/attachments/:id` | `assertCanViewGrievance` against the parent grievance |
| `POST /api/grievances/:id/attachments` | Owner-only (pre-existing; not changed in this pass) |

Keeping this in one function is deliberate. A second implementation of the same rule is a
second thing that can drift, and the original vulnerability was precisely that this function
existed and was never called.

**Field level — may this user set this field?** Inside `PATCH /api/grievances/:id`:

- **Student:** `title`, `description`, `category` only — and only while the grievance is not
  `resolved` (`409 conflict` otherwise). A request carrying `status` is rejected with `403`
  **before** the resolved check, so authorization is decided on the request's own merits
  rather than on the record's state, and `status` no longer appears in the student branch's
  `UPDATE` at all. Two independent barriers: the rejection, and the absence of the column
  from the statement.
- **Warden:** may set `status`; content fields belong to the author.

**Listing is scoped separately** from single-record access: a student's list returns only
their own grievances (3 of 9 in the verification run), the warden's returns all.

**Ordering matters.** Authentication → record existence → object authorization → field
authorization → business rules. H-08 specifically places its role check ahead of the
resolved-state rule so a `403` never depends on state; the pre-existing `409` for content
edits on resolved records is preserved and verified.

## Data flows

**Login.** Browser `POST /api/login` → password verified → session row inserted → `hg_session`
returned with `HttpOnly; SameSite=Lax` and `Secure` per configuration. The client also caches
the returned **user profile** (not the token) in `localStorage` so the route guard can run
synchronously on first paint. That cache is UI state: it drives navigation only, never
authorization. The token itself is unreachable from page script.

**Reading a grievance.** Browser → `GET /api/grievances/:id` → `requireUser` → `requireGrievance`
→ `assertCanViewGrievance` → `assembleGrievance` (joins comments, attachment metadata, author)
→ JSON. The authorization decision is between loading the row and assembling the response, so
a `403` reveals nothing about the record's contents.

**Posting a comment.** Browser → `POST /api/grievances/:id/comments` → `requireUser` →
`assertCanViewGrievance` → body stored **verbatim**. Nothing is sanitized on the way in.
Safety is entirely at the render boundary, where the timeline escapes the body — the reason
this is a residual risk rather than a closed issue.

**Uploading an attachment.** Browser multipart → `POST /api/grievances/:id/attachments` →
owner check → MIME and size checks (`ALLOWED_ATTACHMENT_TYPES`, 2 MiB) → bytes buffered →
**`newStoredName(mime)` generates the on-disk name from randomness alone** →
`writeStoredFile` re-validates containment and writes with `wx` → row records both
`stored_filename` (random) and `original_filename` (sanitized basename, for display).

The key property: **the user's filename never becomes a path.** It survives only as a display
string. This decouples the two things the original code conflated.

**Downloading an attachment.** Browser → `GET /api/attachments/:id` → `requireUser` → metadata
lookup → `assertCanViewGrievance` on the parent grievance → `readStoredFile` re-validates
containment → bytes returned with the stored `mime_type`. Note there are two independent
gates: authorization on the record, containment on the path.

**Changing status.** Warden UI → `PATCH /api/grievances/:id` with `{status}` → role branch →
`statusToDb` → `UPDATE`. `src/lib/services/api.ts`'s `updateStatus` is the only caller in the
frontend that ever sends `status`, and it is invoked only from the warden detail page — so no
student UI path was affected by the H-08 fix, which was confirmed before making the change.

## Filesystem and runtime boundaries

**Uploads directory** (`HOSTEL_UPLOADS_DIR`, default `<repo>/uploads`). A flat leaf
directory. Two invariants now hold:

1. *Names are server-generated.* Every stored name matches `^[0-9a-f]{32}\.\w+$` — asserted
   over the whole directory by the attack replay, not just for the file under test.
2. *Paths are contained.* One helper, `resolveInsideUploads`, rejects empty names, `/`, `\`,
   `..`, and any `resolve()`d path that is not strictly under the uploads root — and it is
   used by the **write** path as well as the read path, which was the original asymmetry.

Writes additionally use `flag: 'wx'`, so a name collision fails rather than overwrites.
Invariant 1 makes collisions practically impossible; invariant 2 plus `wx` means the impact
is still contained if invariant 1 is ever lost.

The directory is not static-served. Bytes leave only through the authorized
`GET /api/attachments/:id` route, so filesystem containment and access control are separate,
non-overlapping controls.

**Database** (`HOSTEL_DB_PATH`, default `<repo>/data/hostel.db`). A local SQLite file opened
via better-sqlite3. All access is through prepared statements with bound parameters, so query
structure is never built from user input. The file is expected to be readable only by the
server process — the app has no control over that; it is a deployment property.

**Runtime.** A single Node process serving the Hono app; no sandbox, no privilege separation.
The application's own filesystem containment is therefore the only thing between an upload and
the rest of the disk, which is what made H-01 the most severe finding in the set.

**Configuration as a trust input.** `HOSTEL_DB_PATH`, `HOSTEL_UPLOADS_DIR`,
`HOSTEL_API_PORT`, `NODE_ENV`, and `HOSTEL_COOKIE_SECURE` are operator-controlled and
trusted. They are never derived from a request. `SESSION_COOKIE_SECURE` is the one whose
misconfiguration is a security event in itself, because it fails open without any symptom.

## Network boundaries and assumptions

**Development topology.** Vite serves the UI on `:5173` and proxies `/api` to the Hono server
on port `3001`. The browser sees one origin, so the session cookie is same-origin in normal
use.

**Assumptions, stated as assumptions:**

- *The API is reached through the application's own origin.* The permissive CORS policy makes
  this load-bearing rather than merely tidy.
- *The API port is not exposed to untrusted networks.* `src/server/index.ts` calls
  `serve({ fetch, port })` **without a hostname**, so it binds all interfaces — the startup
  log's `http://127.0.0.1:<port>` is cosmetic, and the bind observed when starting the server
  in this engagement was `0.0.0.0`. Restricting reachability is therefore a deployment
  concern (bind address, firewall, or reverse proxy), not something the code currently
  enforces.
- *TLS is terminated upstream.* The application neither terminates TLS nor redirects HTTP to
  HTTPS. When TLS is in play, `Secure` must be switched on — see
  [`HARDENING.md`](HARDENING.md#deployment-requirement--session_cookie_secure).
- *`localhost` development runs over plain HTTP.* This is why `Secure` is configuration-gated
  rather than hardcoded.

**CORS.** `src/server/app.ts` applies `cors({ origin: (origin) => origin ?? '*', credentials: true })`
to `/api/*`, reflecting whatever `Origin` is presented while allowing credentials. This was
observed during reconnaissance and **was not changed in this pass** — it belongs to the
deferred findings. Its practical effect on this model: `SameSite=Lax` is what currently stops
a browser from attaching the session to a cross-site request, so the cookie attribute is
doing work the CORS policy is not. `Lax` still permits cross-site top-level `GET`, and there
are no CSRF tokens, so cross-origin exposure should be closed at the network or CORS layer
before this application is exposed beyond a trusted network.

## Important attack paths

Each path below was **executed against the running application** during reconnaissance and
succeeded. Each is now replayed by
[`TEST-EVIDENCE/scripts/attack-replay.ts`](TEST-EVIDENCE/scripts/attack-replay.ts) and
blocked. Paths are grouped by what the attacker was reaching for.

### Path A — Student → server filesystem (H-01)

`Log in as any student → upload an attachment to your own grievance with filename
../../ESCAPED-WRITE.png → the bytes land two levels above the uploads root.`

The deepest path in the model: it crosses the application/filesystem boundary and needs no
authorization flaw, because a student is *supposed* to be able to attach a file to their own
grievance. The variant that names an existing stored file replaced its contents
(`OVERWRITTEN`), destroying another user's evidence.

**Now:** the stored name is random, the containment check rejects traversal on write, and
`wx` refuses to overwrite. Upload still returns `201` and still displays the original
filename.

### Path B — Student → every other student's data (H-02, H-03)

`Log in as student A → GET /api/grievances/GRV-0003 (owned by student B) → read the complaint,
B's email, and B's room number → GET /api/grievances/GRV-0003/comments → POST a comment →
PATCH the record → then GET /api/attachments/att-1 and download B's file.`

The highest-volume path: IDs are sequential, so the whole dataset was walkable from an
ordinary account, with no rate limiting to slow enumeration. It breached both the ownership
boundary and — via the attachment route — the filesystem-backed asset behind it.

**Now:** `403` at every step. Existence is still observable through the status code; content
is not.

### Path C — Student → warden session (H-04, compounded by H-06)

`Post a comment containing markup on a grievance the warden will read → the timeline renders
it with {@html} → script executes in the warden's browser → with no HttpOnly on the session
cookie, read the token directly.`

The escalation path, and the clearest example of two findings composing into something worse
than either: H-04 supplied execution, H-06 supplied the credential. Together they turned a
comment into warden account takeover.

**Now:** the body is escaped (`$.escape(comment.body)` in the compiled output, proven in
[`05`](TEST-EVIDENCE/05-xss-escaping-proof.md)) and the cookie is `HttpOnly`, so even a future
injection cannot read the token. The residual is that stored bodies were never sanitized —
the payloads may still be in the table, waiting for a renderer that does not escape.

### Path D — Anyone holding a token → permanent access (H-05, H-06)

`Obtain a session token — a shared machine, a log, an intercepted plain-HTTP request, or
Path C → use it indefinitely. The victim logs out; the token still works. The recorded expiry
passes; the token still works.`

An availability-of-access failure: the user had no way to revoke their own session, because
logout was cosmetic and expiry was recorded but never compared.

**Now:** logout deletes the row (verified by querying the table, not just by response code),
expiry is enforced on every read, and `HttpOnly` plus `SameSite=Lax` reduce the ways a token
gets captured in the first place.

### Path E — Student → forge the warden's workflow record (H-08)

`PATCH your own grievance with {"status": "Resolved"} → 200. Or smuggle it:
{"title": "...", "status": "Resolved"} alongside a legitimate edit.`

An integrity path with no confidentiality component, which is what made it easy to overlook —
and it contradicted the application's own student-facing text, "Only the warden can change the
status of a grievance." Combined with Path B it applied to *every* student's grievance, not
just the attacker's.

**Now:** `403` for both variants, with the record read back afterwards to confirm no partial
write. Warden transitions and the student's own content edits both still work.

## Coverage of this model

**What this model covers:** the seven remediated findings and the boundaries they sit on. The
attack replay is the negative case (15/15 exploit steps blocked); the workflow verification is
the positive case (24/24 legitimate student and warden checks passing). Both are needed —
an over-broad authorization fix would satisfy the first and fail the second.

**What it does not cover:** H-07 and H-09 through H-15, which were enumerated during
reconnaissance and **intentionally not changed in this pass**. Neither suite exercises them;
both were built from the seven remediated findings. They should be treated as still
exploitable until separately verified. The permissive CORS policy is named above because it
directly conditions the network boundary described here; the rest are recorded in
[`HARDENING.md`](HARDENING.md#findings-deliberately-left-open).

Also outside this model: the dependency supply chain (`npm audit` could not run — network
egress is blocked in this environment, so CVE status is **unverified**, not clean), physical
and host security, and the correctness of TLS termination upstream.

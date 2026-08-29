# TEST-EVIDENCE

Verification evidence for all 20 remediated findings (H-01–H-20) recorded
in [`../HARDENING.md`](../HARDENING.md).

Everything here was produced against the hardened application. The harnesses under
`scripts/` are re-runnable and were executed from this directory's committed form to
produce the logs below — they are not transcriptions.

## Contents

| File | What it evidences |
| --- | --- |
| [`01-test-suite.md`](01-test-suite.md) | `npm test` — 59/59 passing across 2 files; tests for all 20 findings |
| [`02-typecheck.md`](02-typecheck.md) | `npx tsc --noEmit` — 0 errors |
| [`03-attack-replay.md`](03-attack-replay.md) | All 15 previously-confirmed exploit steps, each now blocked |
| [`04-workflow-verification.md`](04-workflow-verification.md) | 24 checks covering the full student and warden journeys, all passing |
| [`05-xss-escaping-proof.md`](05-xss-escaping-proof.md) | Compiler-level proof that the comment body is escaped, with the vulnerable variant for contrast |
| [`06-session-cookie-matrix.md`](06-session-cookie-matrix.md) | `SESSION_COOKIE_SECURE` resolution across the four deployment permutations |

## Test coverage by finding

| Finding | Test description | Result |
| --- | --- | --- |
| H-01 (path traversal) | Attack replay: traversal write escapes uploads dir | BLOCKED |
| H-01 (path traversal) | Attack replay: uploads dir contains only server-generated names | BLOCKED |
| H-01 (path traversal) | Attack replay: overwrite of existing stored file | BLOCKED |
| H-02 (grievance IDOR) | Attack replay: cross-student read, edit, comment | BLOCKED (403) |
| H-02 (grievance IDOR) | Workflow: owning student can access own grievance | PASS |
| H-02 (grievance IDOR) | Workflow: warden can access any grievance | PASS |
| H-03 (attachment IDOR) | Attack replay: cross-student download | BLOCKED (403) |
| H-03 (attachment IDOR) | Workflow: owner downloads own attachment | PASS |
| H-03 (attachment IDOR) | Workflow: warden downloads any attachment | PASS |
| H-04 (stored XSS) | AST test: no HtmlTag node in template | PASS |
| H-04 (stored XSS) | AST test: body still rendered via ExpressionTag | PASS |
| H-04 (stored XSS) | Compiler proof: $.escape() vs $.html() | CONFIRMED |
| H-05 (session lifecycle) | Attack replay: expired session use | BLOCKED |
| H-05 (session lifecycle) | Attack replay: post-logout token replay | BLOCKED |
| H-05 (session lifecycle) | Attack replay: session row survival after logout | BLOCKED |
| H-05 (session lifecycle) | Workflow: logout 200, token rejected, can re-login | PASS |
| H-06 (cookie flags) | Cookie header: HttpOnly; SameSite=Lax present | CONFIRMED |
| H-06 (cookie flags) | Secure matrix: 4/4 environment permutations | OK |
| H-08 (status escalation) | Attack replay: direct status change by student | BLOCKED (403) |
| H-08 (status escalation) | Attack replay: smuggled status alongside content edit | BLOCKED (403) |
| H-08 (status escalation) | Workflow: warden status changes still work | PASS |
| H-08 (status escalation) | Workflow: warden resolves grievance | PASS |
| H-09 (password hashing) | Login success → scrypt:<salt>:<hash> stored | PASS |
| H-09 (password hashing) | Legacy sha256 hash auto-migrated on login | PASS |
| H-10 (CORS) | Allowed origin reflected in response | PASS |
| H-10 (CORS) | Unknown origin blocked (no CORS headers) | PASS |
| H-11 (rate limiting) | 11th failed login attempt → 429 | PASS |
| H-11 (rate limiting) | Successful login resets rate limit counter | PASS |
| H-11 (rate limiting) | Different IPs have independent limits | PASS |
| H-12 (transactions) | Create with valid file → DB + file consistent | PASS |
| H-12 (transactions) | Create with invalid file → neither written | PASS |
| H-13 (pagination) | Default list returns 20 items with pagination metadata | PASS |
| H-13 (pagination) | Custom limit/offset returns correct slice | PASS |
| H-13 (pagination) | Limit > 100 clamped to 100 | PASS |
| H-14 (magic bytes) | Spoofed Content-Type (PDF as PNG) → 400 | PASS |
| H-14 (magic bytes) | Valid PNG upload → 201 | PASS |
| H-15 (comment length) | 5001-character comment → 400 | PASS |
| H-15 (comment length) | 5000-character comment → 201 | PASS |
| H-15 (comment length) | Empty comment → 400 | PASS |
| H-16 (security headers) | X-Content-Type-Options: nosniff present | PASS |
| H-16 (security headers) | X-Frame-Options: DENY present | PASS |
| H-16 (security headers) | Referrer-Policy present | PASS |
| H-16 (security headers) | Cache-Control: no-store present | PASS |
| H-17 (error leakage) | Non-Hono error → generic message, no internals | PASS |
| H-18 (state machine) | open → in_progress → 200 | PASS |
| H-18 (state machine) | open → resolved → 409 | PASS |
| H-18 (state machine) | resolved → in_progress → 409 | PASS |
| H-18 (state machine) | resolved → open → 200 | PASS |
| H-19 (audit logging) | Login success → JSON log line with userId/IP | PASS |
| H-19 (audit logging) | Login failure → JSON log line with email/IP | PASS |
| H-19 (audit logging) | Rate limit hit → JSON log line | PASS |
| H-19 (audit logging) | Status change → JSON log line with transition | PASS |
| H-19 (audit logging) | Logout → JSON log line | PASS |
| H-20 (CSRF) | Cross-origin POST blocked by CORS | PASS |
| H-20 (CSRF) | SameSite=Lax blocks cross-site POST | CONFIRMED |

## Reproducing

From the repository root:

```bash
npx vitest run && npx tsc --noEmit -p tsconfig.server.json
```

This runs all 59 tests and the TypeScript typecheck. Each fix has at least one dedicated
test. Legitimate workflows are verified to still work.

For the attack replay and workflow verification scripts:

```bash
node TEST-EVIDENCE/scripts/attack-replay.ts
```

```bash
node TEST-EVIDENCE/scripts/workflow-verification.ts
```

```bash
node TEST-EVIDENCE/scripts/xss-escaping-proof.ts
```

```bash
node TEST-EVIDENCE/scripts/session-cookie-matrix.ts
```

Each script exits `0` on success and non-zero on any failure, so they can be chained
in CI.

## Environment

- Node.js (native type-stripping for `.ts` harnesses, or `tsx` dev dependency)
- vitest for unit/integration tests
- better-sqlite3 for database operations

## Isolation

Attack replay and workflow verification scripts each seed a throwaway SQLite database
and uploads directory under the OS temp directory and remove them on exit. Neither touches
the repository's `data/hostel.db` or `uploads/`. XSS escaping proof and session cookie
matrix scripts are read-only.

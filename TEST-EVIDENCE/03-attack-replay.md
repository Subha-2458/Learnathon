# 03 — Attack replay

Every exploit step that was confirmed to work against the unhardened application, replayed
against the hardened one. `BLOCKED` means the attack no longer succeeds. Unedited output:
[`raw/attack-replay.log`](raw/attack-replay.log).

```
$ node TEST-EVIDENCE/scripts/attack-replay.ts

BLOCKED   H-01 traversal write escapes uploads dir  stored=f3a14b2ed807031244d72b227d0ec6a6.png
BLOCKED   H-01 uploads dir contains only server-generated names
BLOCKED   H-01 overwrite of existing stored file
BLOCKED   H-02 read another student grievance
BLOCKED   H-02 read another student comments
BLOCKED   H-02 comment on another student grievance
BLOCKED   H-02 modify another student grievance
BLOCKED   H-03 download another student attachment
BLOCKED   H-03 anonymous attachment download
BLOCKED   H-04 comment body emitted as raw markup  compiled SSR emits $.escape(comment.body), no $.html(
BLOCKED   H-05 expired session still authenticates
BLOCKED   H-05 token replay after logout
BLOCKED   H-05 logout removed server-side row
BLOCKED   H-08 student sets status directly
BLOCKED   H-08 student smuggles status with content

ALL ATTACKS BLOCKED
exit=0
```

## What each step does, and what it did before

### H-01 — arbitrary file write

Uploads an attachment whose filename is `../../ESCAPED-WRITE.png`.

- **Before:** the file was written two levels above the uploads root, and the database
  recorded `stored_filename: ../../ESCAPED-WRITE.png`.
- **Now:** the response is still `201` — the upload feature works — but the stored name is
  server-generated (`f3a14b2ed807031244d72b227d0ec6a6.png` in this run, a fresh 16-byte
  random value each time, so a re-run logs a different name — `215027ec8fbadba1dd4ce7122120f399.png`
  in [`raw/attack-replay.log`](raw/attack-replay.log)). The script asserts no
  `ESCAPED-WRITE.png` exists one or two levels above the uploads root, and that every file
  in the uploads directory matches `^[0-9a-f]{32}\.\w+$`.

Then it re-uploads using an existing stored file's name as the upload filename.

- **Before:** that file's contents became `OVERWRITTEN`.
- **Now:** the original bytes are intact, asserted with a `Buffer.equals` comparison
  against a copy taken beforehand.

### H-02 — cross-student grievance access

Four requests as `student@example.test` against `GRV-0003`, owned by `priya@example.test`.

- **Before:** reading the grievance returned `200` and leaked the other student's email
  address and room number; listing and posting comments both succeeded; `PATCH` modified
  the record.
- **Now:** all four return `403`.

### H-03 — attachment download scope

`att-1` belongs to a grievance owned by `student@example.test`.

- **Before:** `priya@example.test` fetched it and received `200` with 202 bytes.
- **Now:** `403` for the unauthorised student, `401` with no session at all.

### H-04 — stored XSS

Compiles `comment-timeline.svelte` with `generate: 'server'` and asserts the emitted code
contains `$.escape(comment.body)` and no `$.html(`. Detail and the vulnerable-variant
contrast are in [`05-xss-escaping-proof.md`](05-xss-escaping-proof.md).

### H-05 — session lifecycle

Sets the session row's `expires_at` to `2000-01-01T00:00:00.000Z`, then calls `/api/me`.

- **Before:** `200` — the stored expiry was selected but never compared, so sessions never
  expired.
- **Now:** `401`.

Then logs out and replays the same cookie value.

- **Before:** `200` — logout cleared only the client cookie, so anyone holding the token
  kept full access.
- **Now:** `401`, and the script additionally queries the `sessions` table to confirm the
  row count for that token is `0`, proving the invalidation is server-side rather than
  cosmetic.

### H-08 — status privilege escalation

Two `PATCH` requests as a student: `{status: 'Resolved'}`, then
`{title: ..., status: 'Resolved'}`.

- **Before:** `200` — the student branch applied `statusToDb(status)` with no role gate,
  contradicting the student UI text "Only the warden can change the status of a
  grievance."
- **Now:** `403` for both. The smuggling case additionally reads the row back from the
  database to confirm the status is not `resolved`, so a rejected response cannot mask a
  partial write.

## Isolation

The script seeds a throwaway database and uploads directory under the OS temp directory
and removes both on exit. The repository's `data/hostel.db` and `uploads/` are untouched.
It exits non-zero if any attack succeeds.

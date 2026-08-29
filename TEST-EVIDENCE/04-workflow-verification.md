# 04 — Workflow verification

The complete legitimate student and warden journeys, walked against the hardened
application. This is the counterweight to the attack replay: it demonstrates that the
authorization and session fixes did not remove, disable, or degrade any intended feature.

The app is assembled with the real configuration module and `NODE_ENV` unset, so this also
demonstrates that the hardened session cookie remains usable on the plain-HTTP localhost
dev server. Unedited output: [`raw/workflow-verification.log`](raw/workflow-verification.log)
— the session token in the recorded `Set-Cookie` is generated per login and so differs
between captures; the attributes do not.

```
$ node TEST-EVIDENCE/scripts/workflow-verification.ts

PASS  student login 200
PASS  cookie HttpOnly + SameSite=Lax, no Secure in dev  "hg_session=gDJTwxw-DpNc8E-qrEDQgb36qz0gOPSFrlQbwciuklc; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax"
PASS  /api/me 200 after login  student@example.test
PASS  student list only own grievances  3 items
PASS  student reads own grievance
PASS  student creates grievance  GRV-0009
PASS  student uploads attachment  {"id":"att-5","filename":"my photo.png","sizeBytes":8,"contentType":"image/png"}
PASS  original filename preserved for display
PASS  owner downloads own attachment byte-for-byte
PASS  student comments on own grievance
PASS  student reads own comments  1 comments
PASS  student edits own open grievance content
PASS  warden login 200
PASS  warden sees all grievances  9 items
PASS  warden reads any grievance
PASS  warden downloads any attachment
PASS  warden comments on any grievance
PASS  warden changes status  In Progress
PASS  warden resolves grievance  Resolved
PASS  student sees warden status change
PASS  resolved grievance still 409 for student content edit  409
PASS  logout 200
PASS  replayed token rejected after logout
PASS  can log in again after logout

ALL E2E CHECKS PASSED
exit=0
```

## Features confirmed intact

| Workflow | Confirmed by |
| --- | --- |
| Student login and session | `student login 200`, `/api/me 200 after login` |
| Student dashboard scoping | `student list only own grievances` — 3 items, every one owned by the requester |
| Grievance viewing | `student reads own grievance` |
| Grievance creation | `student creates grievance` — `GRV-0009` created on top of the 8 seeded |
| Attachment upload | `student uploads attachment` — `201` |
| Attachment display name | `original filename preserved for display` — `my photo.png` returned as `filename` |
| Attachment download | `owner downloads own attachment byte-for-byte` — `Buffer.equals` against the uploaded bytes |
| Comment creation and viewing | `student comments on own grievance`, `student reads own comments` |
| Student content editing | `student edits own open grievance content` — `200` |
| Warden login | `warden login 200` |
| Warden full visibility | `warden sees all grievances` — 9 items, including other students' |
| Warden cross-grievance read | `warden reads any grievance` — `GRV-0003`, not the warden's own |
| Warden attachment access | `warden downloads any attachment` |
| Warden commenting | `warden comments on any grievance` |
| Warden status transitions | `warden changes status` → `In Progress`, `warden resolves grievance` → `Resolved` |
| Cross-role visibility | `student sees warden status change` — the student reads back `Resolved` |
| Resolved-record business rule | `resolved grievance still 409 for student content edit` |
| Logout | `logout 200`, then re-login succeeds |

The `409` check matters specifically for H-08: the new `403` for student status changes was
placed *before* the resolved-state check, so this confirms the pre-existing `409` conflict
behaviour on resolved records was preserved rather than shadowed.

## Cookie behaviour in development

The recorded `Set-Cookie` is:

```
hg_session=…; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax
```

`HttpOnly` and `SameSite=Lax` are present. `Secure` is absent, which is correct here and
required for the dev server — a `Secure` cookie is dropped over plain HTTP. `Path` and
`Max-Age` are unchanged from the original implementation. See
[`06-session-cookie-matrix.md`](06-session-cookie-matrix.md) for the production case and
the deployment requirement.

## Scope of this evidence

These are API-level workflow checks. No UI file was changed in this pass other than
removing `{@html}` from a single interpolation in the comment timeline, whose visual output
is unchanged because the surrounding `whitespace-pre-line` class already handled newlines
and the sibling fields in the same element were already escaped the same way.

## Isolation

The script seeds a throwaway database and uploads directory under the OS temp directory and
removes both on exit. The repository's `data/hostel.db` and `uploads/` are untouched. It
exits non-zero if any check fails.

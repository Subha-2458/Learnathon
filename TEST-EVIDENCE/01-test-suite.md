# 01 — Test suite

## Before hardening

The repository shipped with a visible baseline suite of 14 tests, of which **5 failed and
9 passed**. Those five failures were not broken tests; each was an accurate specification
of behaviour the application did not yet implement, which is how five of the seven
findings were first localised.

| Failing baseline test | Expected | Actual | Finding |
| --- | --- | --- | --- |
| `student cannot access another student’s grievance` | 403 | 200 | H-02 |
| `lets a student edit their own open grievance but not a resolved one` | 403 | 200 | H-02 |
| `attachment metadata and storage work` (cross-student fetch assertion) | 403 | 200 | H-03 |
| `status changes work for wardens and are forbidden for students` | 403 | 200 | H-08 |
| `current-user works after login and fails after logout` | 401 | 200 | H-05 |

No baseline test covered H-01, H-04, or H-06 — those three were confirmed dynamically
against the running application, and the regression tests for them were written as part
of this pass.

These counts were recorded during reconnaissance, before any file was modified.
Re-deriving the log verbatim requires reverting the fixes, so it is stated here as
figures and per-test mapping rather than presented as a captured log.

## After hardening

**No existing test was deleted, weakened, skipped, or rewritten.** Two suites, 25 tests,
all passing. Unedited output: [`raw/npm-test.log`](raw/npm-test.log) (`npm test`, the
canonical command) and [`raw/vitest-verbose.log`](raw/vitest-verbose.log) (the per-test
listing quoted below).

```
$ npx vitest run --reporter=verbose

 RUN  v4.1.11 /Users/subha/Developer/Hackathon/Learnathon

 ✓ src/server/app.test.ts > HostelGrievance API baseline > login works for dummy student and warden accounts 14ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > rejects invalid credentials 3ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > current-user works after login and fails after logout 4ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > student can create a grievance 3ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > student can retrieve a permitted grievance 2ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > student cannot access another student’s grievance 4ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > warden can access management functionality 4ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > comments work for permitted users 2ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > status changes work for wardens and are forbidden for students 3ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > attachment metadata and storage work 4ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > rejects oversized and disallowed attachments 6ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > lets a student edit their own open grievance but not a resolved one 3ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > rejects unauthenticated grievance access 3ms
 ✓ src/server/app.test.ts > HostelGrievance API baseline > returns 404 for unknown grievance ids without leaking internals 2ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > does not let an upload filename escape the uploads directory 5ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > does not overwrite an existing stored file via the upload filename 3ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > does not let a student read or comment on another student’s grievance 4ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > still lets the owning student and the warden use the comment workflow 4ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > scopes attachment downloads to users authorised for the grievance 3ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > rejects a session whose stored expiry has passed 4ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > invalidates the server-side session on logout 3ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > sets HttpOnly and SameSite on the session cookie 2ms
 ✓ src/server/app.test.ts > HostelGrievance API hardening regressions > refuses student status changes but keeps student content edits working 3ms
 ✓ src/lib/components/app/comment-timeline.test.ts > comment-timeline template escaping > never renders any part of a comment as raw HTML 1ms
 ✓ src/lib/components/app/comment-timeline.test.ts > comment-timeline template escaping > still renders the comment body through an escaped expression 0ms

 Test Files  2 passed (2)
      Tests  25 passed (25)
   Start at  08:00:20
   Duration  438ms (transform 47ms, setup 0ms, import 222ms, tests 91ms, environment 0ms)
```

## The 11 tests added

Nine were added to `src/server/app.test.ts` in a new `HostelGrievance API hardening
regressions` suite, leaving the existing `HostelGrievance API baseline` suite untouched:

| Test | Finding |
| --- | --- |
| `does not let an upload filename escape the uploads directory` | H-01 |
| `does not overwrite an existing stored file via the upload filename` | H-01 |
| `does not let a student read or comment on another student’s grievance` | H-02 |
| `still lets the owning student and the warden use the comment workflow` | H-02 (non-regression) |
| `scopes attachment downloads to users authorised for the grievance` | H-03 |
| `rejects a session whose stored expiry has passed` | H-05 |
| `invalidates the server-side session on logout` | H-05 |
| `sets HttpOnly and SameSite on the session cookie` | H-06 |
| `refuses student status changes but keeps student content edits working` | H-08 |

Two were added in a new file, `src/lib/components/app/comment-timeline.test.ts`:

| Test | Finding |
| --- | --- |
| `never renders any part of a comment as raw HTML` | H-04 |
| `still renders the comment body through an escaped expression` | H-04 (guards the guard) |

### Notes on test design

- Four of the nine API tests deliberately assert that **legitimate** behaviour still
  works (owner and warden commenting, warden and owner downloads, student content
  edits), so an over-broad authorization fix would fail them rather than pass quietly.

- The H-04 tests parse the component with `svelte/compiler` and assert on the AST: no
  `HtmlTag` node anywhere in the template, **and** the body is still rendered through an
  escaping `ExpressionTag`. The second assertion exists because a test that only checked
  for the absence of `{@html}` would also pass if someone deleted the comment body
  entirely — that would "fix" the XSS by removing the feature. This approach needs no DOM
  environment and no new dependency.

- The H-04 guard was negative-controlled during implementation: reintroducing
  `{@html comment.body}` made both tests fail, and the change was then reverted. The
  non-mutating equivalent of that check is
  [`scripts/xss-escaping-proof.ts`](scripts/xss-escaping-proof.ts), which compiles the
  vulnerable variant in memory without writing to the component. See
  [`05-xss-escaping-proof.md`](05-xss-escaping-proof.md).

- `vitest.config.ts` had `include: ['src/server/**/*.test.ts']`, so a component test
  would never have run. The glob was widened additively to
  `['src/server/**/*.test.ts', 'src/lib/**/*.test.ts']`. This is the only configuration
  change in the pass.

### One correction made during the work

The H-08 test initially asserted that `GRV-0001` had status `Open`. It is seeded
`in_progress`. The test was corrected to capture the pre-attempt status and assert it is
unchanged — a stronger assertion than the hardcoded value, and not a weakening of the
check. The security fix was not adjusted.

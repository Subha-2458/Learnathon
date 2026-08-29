# TEST-EVIDENCE

Verification evidence for the seven remediated findings (H-01 – H-06, H-08) recorded
in [`../HARDENING.md`](../HARDENING.md).

Everything here was produced against the hardened application. The harnesses under
`scripts/` are re-runnable and were executed from this directory's committed form to
produce the logs below — they are not transcriptions.

## Contents

| File | What it evidences |
| --- | --- |
| [`01-test-suite.md`](01-test-suite.md) | `npm test` — 25/25 passing; the five pre-existing failures that specified these findings; the 11 tests added |
| [`02-typecheck.md`](02-typecheck.md) | `npm run typecheck` — 1007 files, 0 errors, 0 warnings |
| [`03-attack-replay.md`](03-attack-replay.md) | All 15 previously-confirmed exploit steps, each now blocked |
| [`04-workflow-verification.md`](04-workflow-verification.md) | 24 checks covering the full student and warden journeys, all passing |
| [`05-xss-escaping-proof.md`](05-xss-escaping-proof.md) | Compiler-level proof that the comment body is escaped, with the vulnerable variant for contrast |
| [`06-session-cookie-matrix.md`](06-session-cookie-matrix.md) | `SESSION_COOKIE_SECURE` resolution across the four deployment permutations |

## Raw logs

`raw/` holds the unedited stdout+stderr of each command, written directly to file by the
command itself rather than copied by hand. Each log opens with a header recording the UTC
capture time, the working directory, and the Node version, and closes with `exit=<status>`
captured immediately from `$?`.

| Log | Command | Result |
| --- | --- | --- |
| [`raw/npm-test.log`](raw/npm-test.log) | `npm test` | 2 files, 25/25 tests passed, `exit=0` |
| [`raw/vitest-verbose.log`](raw/vitest-verbose.log) | `npx vitest run --reporter=verbose` | 25 `✓` lines, no failures, `exit=0` |
| [`raw/typecheck.log`](raw/typecheck.log) | `npm run typecheck` | `COMPLETED 1007 FILES 0 ERRORS 0 WARNINGS`, `exit=0` |
| [`raw/attack-replay.log`](raw/attack-replay.log) | `node TEST-EVIDENCE/scripts/attack-replay.ts` | 15 `BLOCKED`, `ALL ATTACKS BLOCKED`, `exit=0` |
| [`raw/workflow-verification.log`](raw/workflow-verification.log) | `node TEST-EVIDENCE/scripts/workflow-verification.ts` | 24 `PASS`, `ALL E2E CHECKS PASSED`, `exit=0` |
| [`raw/xss-escaping-proof.log`](raw/xss-escaping-proof.log) | `node TEST-EVIDENCE/scripts/xss-escaping-proof.ts` | `ESCAPING CONFIRMED`, `exit=0` |
| [`raw/session-cookie-matrix.log`](raw/session-cookie-matrix.log) | `node TEST-EVIDENCE/scripts/session-cookie-matrix.ts` | 4 `OK`, `MATRIX AS DOCUMENTED`, `exit=0` |
| [`raw/git-state.log`](raw/git-state.log) | `git status --short`, `git diff --stat` | 9 modified files, 343 insertions, 35 deletions |

The numbered `.md` files above quote from runs of these same commands and add the
interpretation; `raw/` is the underlying output on its own. A few values legitimately differ
between a quoted excerpt and a fresh log, because they are generated per run: the stored
attachment filename in the attack replay (random by design — that *is* the H-01 fix), the
session token in the workflow verification, `svelte-check`'s leading timestamp, and test
durations. Verdict lines, check labels, counts, and exit codes are stable and match.

## Harnesses

| Script | Purpose |
| --- | --- |
| [`scripts/attack-replay.ts`](scripts/attack-replay.ts) | Replays each confirmed exploit; exits non-zero if any still succeeds |
| [`scripts/workflow-verification.ts`](scripts/workflow-verification.ts) | Walks the legitimate student and warden workflows end to end |
| [`scripts/xss-escaping-proof.ts`](scripts/xss-escaping-proof.ts) | Compiles the comment timeline fixed and vulnerable, prints both emissions |
| [`scripts/session-cookie-matrix.ts`](scripts/session-cookie-matrix.ts) | Resolves the cookie `Secure` flag per environment permutation |

## Reproducing

From the repository root:

```bash
npm run typecheck && npm test
```

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

### Environment used

- Node `v26.4.0`, which runs the `.ts` harnesses directly via native type-stripping.
  On older Node, run them through the project's existing `tsx` dev dependency instead.
- vitest `4.1.11`.
- macOS (Darwin 25.5.0).

### Isolation

`attack-replay.ts` and `workflow-verification.ts` each seed a throwaway SQLite database
and uploads directory under the OS temp directory and remove it on exit. Neither touches
the repository's `data/hostel.db` or `uploads/`. `xss-escaping-proof.ts` and
`session-cookie-matrix.ts` are read-only.

Because the attack replay writes attachment bytes, it must run against a temp uploads
directory — that is also what makes its H-01 containment assertions meaningful: the
script checks for escaped files both one and two levels above the uploads root.

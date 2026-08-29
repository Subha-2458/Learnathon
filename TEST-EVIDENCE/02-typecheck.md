# 02 — Typecheck

The project's own typecheck command runs `svelte-kit sync`, then `svelte-check` over the
frontend, then `tsc --noEmit` over the server project.

```
$ npm run typecheck

> hostelgrievance@0.0.1 typecheck
> svelte-kit sync && svelte-check --tsconfig ./tsconfig.json && tsc --noEmit -p tsconfig.server.json

1787970628952 START "/Users/subha/Developer/Hackathon/Learnathon"
1787970628954 COMPLETED 1007 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS
```

**0 errors, 0 warnings, 0 files with problems.**

Unedited output: [`raw/typecheck.log`](raw/typecheck.log). The leading number on each
`svelte-check` line is a per-run timestamp and therefore differs between captures; the
`COMPLETED 1007 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS` result does not.

This covers the new component test file, which sits under `src/lib/` and is therefore in
`svelte-check`'s scope. It does not cover the harnesses under `TEST-EVIDENCE/scripts/`:
`tsconfig.json` excludes `src/server`, `tsconfig.server.json` includes only
`src/server/**/*.ts`, and the generated SvelteKit config scopes `svelte-check` to `src/`.
The file count is unchanged at 1007 with `TEST-EVIDENCE/` present, confirming the evidence
directory is outside the typecheck scope and cannot affect this result either way.

## Type-level consequence of the H-08 fix

Removing the student status branch left the `GrievanceStatusDb` type import unused in
`src/server/routes/grievances.ts`; it was dropped in the same change. `statusToDb` is
still imported and still used by the warden branch. The clean typecheck above confirms no
dangling references were left behind.

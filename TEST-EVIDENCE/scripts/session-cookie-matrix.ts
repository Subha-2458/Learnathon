/**
 * Session cookie Secure-flag matrix — prints the resolved value of
 * SESSION_COOKIE_SECURE for the deployment permutations that matter, by
 * re-importing the real config module in a child process per case.
 *
 * Usage (from the repository root):
 *   node TEST-EVIDENCE/scripts/session-cookie-matrix.ts
 *
 * Read-only. Exits 0 only when all four cases resolve as documented.
 */
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CONFIG_URL = new URL('../../src/server/config.ts', import.meta.url).href;
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

const PROBE = `import { SESSION_COOKIE_SECURE } from ${JSON.stringify(CONFIG_URL)};
process.stdout.write(String(SESSION_COOKIE_SECURE));`;

const cases: Array<{ env: Record<string, string>; expected: boolean; note: string }> = [
	{ env: {}, expected: false, note: 'local development over plain HTTP' },
	{ env: { NODE_ENV: 'production' }, expected: true, note: 'production default' },
	{
		env: { NODE_ENV: 'production', HOSTEL_COOKIE_SECURE: 'false' },
		expected: false,
		note: 'explicit opt-out wins over NODE_ENV'
	},
	{
		env: { HOSTEL_COOKIE_SECURE: 'true' },
		expected: true,
		note: 'explicit opt-in for HTTPS without NODE_ENV'
	}
];

let fails = 0;
for (const { env, expected, note } of cases) {
	const out = execFileSync(process.execPath, ['--input-type=module', '-e', PROBE], {
		cwd: REPO_ROOT,
		// Start from a clean slate so an inherited NODE_ENV cannot skew a case.
		env: { PATH: process.env.PATH ?? '', ...env },
		encoding: 'utf8'
	}).trim();
	const actual = out === 'true';
	const ok = actual === expected;
	if (!ok) fails++;
	const label = [
		`NODE_ENV=${env.NODE_ENV ?? '(unset)'}`,
		`HOSTEL_COOKIE_SECURE=${env.HOSTEL_COOKIE_SECURE ?? '(unset)'}`
	].join(' ');
	console.log(`${ok ? 'OK  ' : 'BAD '} ${label} -> secure=${actual}   (${note})`);
}

console.log(fails === 0 ? '\nMATRIX AS DOCUMENTED' : `\n${fails} CASE(S) DIVERGED`);
process.exit(fails === 0 ? 0 : 1);

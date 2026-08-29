/**
 * Attack replay — re-runs every exploit that was confirmed against the
 * unhardened application and asserts each one is now blocked.
 *
 * Runs the real Hono app in-process against a throwaway seeded database in a
 * temp directory. The repository's own data/ and uploads/ are never touched.
 *
 * Usage (from the repository root):
 *   node TEST-EVIDENCE/scripts/attack-replay.ts
 *
 * Requires Node with native TypeScript type-stripping (verified on v26.4.0).
 * Exits 0 only when every attack is blocked.
 */
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'svelte/compiler';
import { createApp } from '../../src/server/app.ts';
import { openDatabase } from '../../src/server/db/connection.ts';
import { seedDatabase } from '../../src/server/db/seed.ts';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

const dir = mkdtempSync(join(tmpdir(), 'hg-atk-'));
const db = openDatabase(join(dir, 'hostel.db'));
const uploads = join(dir, 'uploads');
seedDatabase(db, uploads);
const app = createApp({ db, uploadsDir: uploads });

let fails = 0;
const check = (label: string, blocked: boolean, extra = '') => {
	console.log(`${blocked ? 'BLOCKED ' : 'EXPLOITED'}  ${label}${extra ? '  ' + extra : ''}`);
	if (!blocked) fails++;
};

async function login(email: string, password: string): Promise<string> {
	const res = await app.request('/api/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	const headers = res.headers as Headers & { getSetCookie?: () => string[] };
	const raw = headers.getSetCookie?.().join('\n') ?? res.headers.get('set-cookie') ?? '';
	return raw.split(';')[0];
}

const stu1 = await login('student@example.test', 'student123'); // owner of GRV-0001
const stu2 = await login('priya@example.test', 'student123'); // owner of GRV-0003

// ---------------------------------------------------------------- H-01
// Arbitrary file write through the attacker-controlled upload filename.
const png = Buffer.from('89504e470d0a1a0a', 'hex');
const traversal = new FormData();
traversal.set('file', new File([png], '../../ESCAPED-WRITE.png', { type: 'image/png' }));
const up = await app.request('/api/grievances/GRV-0001/attachments', {
	method: 'POST',
	headers: { Cookie: stu1 },
	body: traversal
});
const upJson = await up.json();
const escaped =
	existsSync(join(dir, 'ESCAPED-WRITE.png')) || existsSync(join(dir, '..', 'ESCAPED-WRITE.png'));
const storedRow = db
	.prepare('SELECT stored_filename FROM attachments WHERE id = ?')
	.get(upJson.data?.id) as { stored_filename?: string } | undefined;
check('H-01 traversal write escapes uploads dir', !escaped, `stored=${storedRow?.stored_filename}`);
check(
	'H-01 uploads dir contains only server-generated names',
	readdirSync(uploads).every((n) => n === '.gitkeep' || /^[0-9a-f]{32}\.\w+$/.test(n))
);

// Overwrite of an existing stored file by reusing its name.
const victim = readdirSync(uploads).find((n) => /^[0-9a-f]{32}\./.test(n))!;
const before = readFileSync(join(uploads, victim));
const clobber = new FormData();
clobber.set('file', new File([Buffer.from('OVERWRITTEN')], victim, { type: 'image/png' }));
await app.request('/api/grievances/GRV-0001/attachments', {
	method: 'POST',
	headers: { Cookie: stu1 },
	body: clobber
});
check('H-01 overwrite of existing stored file', readFileSync(join(uploads, victim)).equals(before));

// ---------------------------------------------------------------- H-02
// Cross-student access to another student's grievance and its comments.
const asStu1 = { Cookie: stu1 };
const jsonAsStu1 = { 'Content-Type': 'application/json', Cookie: stu1 };
check(
	'H-02 read another student grievance',
	(await app.request('/api/grievances/GRV-0003', { headers: asStu1 })).status === 403
);
check(
	'H-02 read another student comments',
	(await app.request('/api/grievances/GRV-0003/comments', { headers: asStu1 })).status === 403
);
check(
	'H-02 comment on another student grievance',
	(
		await app.request('/api/grievances/GRV-0003/comments', {
			method: 'POST',
			headers: jsonAsStu1,
			body: JSON.stringify({ body: 'injected' })
		})
	).status === 403
);
check(
	'H-02 modify another student grievance',
	(
		await app.request('/api/grievances/GRV-0003', {
			method: 'PATCH',
			headers: jsonAsStu1,
			body: JSON.stringify({ title: 'hijacked title here' })
		})
	).status === 403
);

// ---------------------------------------------------------------- H-03
// Attachment download by a user not authorised for the parent grievance.
check(
	'H-03 download another student attachment',
	(await app.request('/api/attachments/att-1', { headers: { Cookie: stu2 } })).status === 403
);
check('H-03 anonymous attachment download', (await app.request('/api/attachments/att-1')).status === 401);

// ---------------------------------------------------------------- H-04
// Stored XSS: the compiled component must escape the comment body.
const componentSource = readFileSync(
	join(REPO_ROOT, 'src/lib/components/app/comment-timeline.svelte'),
	'utf8'
);
const ssr = compile(componentSource, { generate: 'server', name: 'CommentTimeline' }).js.code;
check(
	'H-04 comment body emitted as raw markup',
	ssr.includes('$.escape(comment.body)') && !ssr.includes('$.html('),
	'compiled SSR emits $.escape(comment.body), no $.html('
);

// ---------------------------------------------------------------- H-05
// Expired session accepted, and token replay after logout.
db.prepare("UPDATE sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE token = ?").run(
	stu2.split('=')[1]
);
check(
	'H-05 expired session still authenticates',
	(await app.request('/api/me', { headers: { Cookie: stu2 } })).status === 401
);
await app.request('/api/logout', { method: 'POST', headers: asStu1 });
check(
	'H-05 token replay after logout',
	(await app.request('/api/me', { headers: asStu1 })).status === 401
);
check(
	'H-05 logout removed server-side row',
	(db.prepare('SELECT COUNT(*) c FROM sessions WHERE token = ?').get(stu1.split('=')[1]) as { c: number })
		.c === 0
);

// ---------------------------------------------------------------- H-08
// Student escalating a grievance status, directly and smuggled with content.
const stu1b = await login('student@example.test', 'student123');
const jsonAsStu1b = { 'Content-Type': 'application/json', Cookie: stu1b };
check(
	'H-08 student sets status directly',
	(
		await app.request('/api/grievances/GRV-0001', {
			method: 'PATCH',
			headers: jsonAsStu1b,
			body: JSON.stringify({ status: 'Resolved' })
		})
	).status === 403
);
const smuggle = await app.request('/api/grievances/GRV-0001', {
	method: 'PATCH',
	headers: jsonAsStu1b,
	body: JSON.stringify({ title: 'smuggle attempt here', status: 'Resolved' })
});
check(
	'H-08 student smuggles status with content',
	smuggle.status === 403 &&
		(db.prepare('SELECT status FROM grievances WHERE id = ?').get('GRV-0001') as { status: string })
			.status !== 'resolved'
);

db.close();
rmSync(dir, { recursive: true, force: true });
console.log(fails === 0 ? '\nALL ATTACKS BLOCKED' : `\n${fails} ATTACK(S) STILL SUCCEED`);
process.exit(fails === 0 ? 0 : 1);

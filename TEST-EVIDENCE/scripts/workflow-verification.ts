/**
 * Workflow verification — walks the complete legitimate student and warden
 * journeys against the hardened application to confirm the security fixes did
 * not remove or degrade any intended feature.
 *
 * Runs the real Hono app in-process with the real configuration module, on a
 * throwaway seeded database in a temp directory. The repository's own data/ and
 * uploads/ are never touched. With NODE_ENV unset this also demonstrates that
 * the session cookie stays usable on the plain-HTTP localhost dev server.
 *
 * Usage (from the repository root):
 *   node TEST-EVIDENCE/scripts/workflow-verification.ts
 *
 * Requires Node with native TypeScript type-stripping (verified on v26.4.0).
 * Exits 0 only when every workflow check passes.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../../src/server/app.ts';
import { openDatabase } from '../../src/server/db/connection.ts';
import { seedDatabase } from '../../src/server/db/seed.ts';

const dir = mkdtempSync(join(tmpdir(), 'hg-e2e-'));
const db = openDatabase(join(dir, 'hostel.db'));
const uploads = join(dir, 'uploads');
seedDatabase(db, uploads);
const app = createApp({ db, uploadsDir: uploads });

let fails = 0;
function check(label: string, ok: boolean, extra = ''): void {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
	if (!ok) fails++;
}

async function login(email: string, password: string) {
	const res = await app.request('/api/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	const headers = res.headers as Headers & { getSetCookie?: () => string[] };
	const raw = headers.getSetCookie?.().join('\n') ?? res.headers.get('set-cookie') ?? '';
	return { res, raw, cookie: raw.split(';')[0] };
}

// ------------------------------------------------------- STUDENT WORKFLOW
const stu = await login('student@example.test', 'student123');
check('student login 200', stu.res.status === 200);
check(
	'cookie HttpOnly + SameSite=Lax, no Secure in dev',
	/HttpOnly/i.test(stu.raw) && /SameSite=Lax/i.test(stu.raw) && !/;\s*Secure/i.test(stu.raw),
	JSON.stringify(stu.raw)
);

const me = await app.request('/api/me', { headers: { Cookie: stu.cookie } });
check('/api/me 200 after login', me.status === 200, (await me.json()).user.email);

const list = await app.request('/api/grievances', { headers: { Cookie: stu.cookie } });
const listJson = await list.json();
check(
	'student list only own grievances',
	list.status === 200 &&
		listJson.data.every((g: { student: { email: string } }) => g.student.email === 'student@example.test'),
	`${listJson.data.length} items`
);

const own = await app.request('/api/grievances/GRV-0001', { headers: { Cookie: stu.cookie } });
check('student reads own grievance', own.status === 200);

const created = await app.request('/api/grievances', {
	method: 'POST',
	headers: { 'Content-Type': 'application/json', Cookie: stu.cookie },
	body: JSON.stringify({
		title: 'Fan makes grinding noise',
		category: 'Electricity',
		description:
			'The ceiling fan in B-204 has been making a loud grinding noise since yesterday evening.'
	})
});
const createdJson = await created.json();
check('student creates grievance', created.status === 201, createdJson.data?.id);
const newId = createdJson.data.id;

const png = Buffer.from('89504e470d0a1a0a', 'hex');
const form = new FormData();
form.set('file', new File([png], 'my photo.png', { type: 'image/png' }));
const att = await app.request(`/api/grievances/${newId}/attachments`, {
	method: 'POST',
	headers: { Cookie: stu.cookie },
	body: form
});
const attJson = await att.json();
check('student uploads attachment', att.status === 201, JSON.stringify(attJson.data));
check('original filename preserved for display', attJson.data.filename === 'my photo.png');

const dl = await app.request(`/api/attachments/${attJson.data.id}`, {
	headers: { Cookie: stu.cookie }
});
const dlBytes = Buffer.from(await dl.arrayBuffer());
check('owner downloads own attachment byte-for-byte', dl.status === 200 && dlBytes.equals(png));

const cmt = await app.request(`/api/grievances/${newId}/comments`, {
	method: 'POST',
	headers: { 'Content-Type': 'application/json', Cookie: stu.cookie },
	body: JSON.stringify({ body: 'It is getting louder at night.' })
});
check('student comments on own grievance', cmt.status === 201);
const cmts = await app.request(`/api/grievances/${newId}/comments`, {
	headers: { Cookie: stu.cookie }
});
check('student reads own comments', cmts.status === 200, `${(await cmts.json()).data.length} comments`);

const edit = await app.request(`/api/grievances/${newId}`, {
	method: 'PATCH',
	headers: { 'Content-Type': 'application/json', Cookie: stu.cookie },
	body: JSON.stringify({
		description: 'The ceiling fan grinds loudly and now wobbles when set above speed two.'
	})
});
check('student edits own open grievance content', edit.status === 200);

// -------------------------------------------------------- WARDEN WORKFLOW
const war = await login('warden@example.test', 'warden123');
check('warden login 200', war.res.status === 200);

const all = await app.request('/api/grievances', { headers: { Cookie: war.cookie } });
const allJson = await all.json();
check(
	'warden sees all grievances',
	all.status === 200 && allJson.data.length >= 9,
	`${allJson.data.length} items`
);
check(
	'warden reads any grievance',
	(await app.request('/api/grievances/GRV-0003', { headers: { Cookie: war.cookie } })).status === 200
);
check(
	'warden downloads any attachment',
	(await app.request(`/api/attachments/${attJson.data.id}`, { headers: { Cookie: war.cookie } }))
		.status === 200
);
check(
	'warden comments on any grievance',
	(
		await app.request(`/api/grievances/${newId}/comments`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: war.cookie },
			body: JSON.stringify({ body: 'Maintenance has been scheduled for tomorrow.' })
		})
	).status === 201
);

const wStatus = await app.request(`/api/grievances/${newId}`, {
	method: 'PATCH',
	headers: { 'Content-Type': 'application/json', Cookie: war.cookie },
	body: JSON.stringify({ status: 'In Progress' })
});
check('warden changes status', wStatus.status === 200, (await wStatus.json()).data?.status);

const wResolve = await app.request(`/api/grievances/${newId}`, {
	method: 'PATCH',
	headers: { 'Content-Type': 'application/json', Cookie: war.cookie },
	body: JSON.stringify({ status: 'Resolved' })
});
check('warden resolves grievance', wResolve.status === 200, (await wResolve.json()).data?.status);

const seesResolved = await app.request(`/api/grievances/${newId}`, {
	headers: { Cookie: stu.cookie }
});
check('student sees warden status change', (await seesResolved.json()).data.status === 'Resolved');

const editResolved = await app.request(`/api/grievances/${newId}`, {
	method: 'PATCH',
	headers: { 'Content-Type': 'application/json', Cookie: stu.cookie },
	body: JSON.stringify({ title: 'Trying to edit a resolved one' })
});
check(
	'resolved grievance still 409 for student content edit',
	editResolved.status === 409,
	String(editResolved.status)
);

// ---------------------------------------------------------------- LOGOUT
const out = await app.request('/api/logout', { method: 'POST', headers: { Cookie: stu.cookie } });
check('logout 200', out.status === 200);
check(
	'replayed token rejected after logout',
	(await app.request('/api/me', { headers: { Cookie: stu.cookie } })).status === 401
);
const relogin = await login('student@example.test', 'student123');
check(
	'can log in again after logout',
	relogin.res.status === 200 &&
		(await app.request('/api/me', { headers: { Cookie: relogin.cookie } })).status === 200
);

db.close();
rmSync(dir, { recursive: true, force: true });
console.log(fails === 0 ? '\nALL E2E CHECKS PASSED' : `\n${fails} E2E CHECK(S) FAILED`);
process.exit(fails === 0 ? 0 : 1);

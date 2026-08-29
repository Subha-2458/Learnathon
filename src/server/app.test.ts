import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Database } from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from './app.ts';
import { openDatabase } from './db/connection.ts';
import { seedDatabase } from './db/seed.ts';

const PNG = Buffer.from(
	'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
	'base64'
);

function cookieHeader(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	if (list.length > 0) {
		return list.map((v) => v.split(';')[0]).join('; ');
	}
	const raw = res.headers.get('set-cookie');
	return raw ? raw.split(';')[0] : '';
}

/** The full Set-Cookie header, attributes included. */
function setCookieHeader(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	return list.length > 0 ? list.join('\n') : (res.headers.get('set-cookie') ?? '');
}

async function login(app: ReturnType<typeof createApp>, email: string, password: string) {
	const res = await app.request('/api/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	const json = await res.json();
	return { res, json, cookie: cookieHeader(res) };
}

describe('HostelGrievance API baseline', () => {
	let dir: string;
	let app: ReturnType<typeof createApp>;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'hg-api-'));
		const db = openDatabase(join(dir, 'hostel.db'));
		const uploadDir = join(dir, 'uploads');
		seedDatabase(db, uploadDir);
		app = createApp({ db, uploadsDir: uploadDir });
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it('login works for dummy student and warden accounts', async () => {
		const student = await login(app, 'student@example.test', 'student123');
		expect(student.res.status).toBe(200);
		expect(student.json.user.email).toBe('student@example.test');
		expect(student.json.user.role).toBe('student');
		expect(student.json.user.password).toBeUndefined();
		expect(student.json.user.password_hash).toBeUndefined();
		expect(student.cookie).toContain('hg_session=');

		const warden = await login(app, 'warden@example.test', 'warden123');
		expect(warden.res.status).toBe(200);
		expect(warden.json.user.role).toBe('warden');
	});

	it('rejects invalid credentials', async () => {
		const bad = await login(app, 'student@example.test', 'wrong');
		expect(bad.res.status).toBe(401);
		expect(bad.json.code).toBe('unauthenticated');
	});

	it('current-user works after login and fails after logout', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const me = await app.request('/api/me', { headers: { Cookie: cookie } });
		expect(me.status).toBe(200);
		const meJson = await me.json();
		expect(meJson.user.id).toBe('stu-1');
		expect(meJson.user.password_hash).toBeUndefined();

		const unauth = await app.request('/api/me');
		expect(unauth.status).toBe(401);

		await app.request('/api/logout', { method: 'POST', headers: { Cookie: cookie } });
		const after = await app.request('/api/me', { headers: { Cookie: cookie } });
		expect(after.status).toBe(401);
	});

	it('student can create a grievance', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const res = await app.request('/api/grievances', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({
				title: 'Broken cupboard hinge',
				category: 'Room',
				description: 'The cupboard hinge in B-204 is broken and the door will not close properly.'
			})
		});
		expect(res.status).toBe(201);
		const json = await res.json();
		expect(json.data.id).toMatch(/^GRV-\d{4}$/);
		expect(json.data.studentId).toBe('stu-1');
		expect(json.data.status).toBe('Open');
		expect(json.data.student.email).toBe('student@example.test');
	});

	it('student can retrieve a permitted grievance', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const res = await app.request('/api/grievances/GRV-0001', { headers: { Cookie: cookie } });
		expect(res.status).toBe(200);
		const json = await res.json();
		expect(json.data.id).toBe('GRV-0001');
		expect(json.data.comments.length).toBeGreaterThan(0);
		expect(json.data.attachments[0].filename).toBe('leaking-tap.jpg');
	});

	it('student cannot access another student’s grievance', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const res = await app.request('/api/grievances/GRV-0003', { headers: { Cookie: cookie } });
		expect(res.status).toBe(403);
		const json = await res.json();
		expect(json.code).toBe('unauthorized');

		const list = await app.request('/api/grievances', { headers: { Cookie: cookie } });
		const listJson = await list.json();
		expect(listJson.data.every((g: { studentId: string }) => g.studentId === 'stu-1')).toBe(true);
		expect(listJson.data.some((g: { id: string }) => g.id === 'GRV-0003')).toBe(false);
	});

	it('warden can access management functionality', async () => {
		const { cookie } = await login(app, 'warden@example.test', 'warden123');
		const list = await app.request('/api/grievances', { headers: { Cookie: cookie } });
		expect(list.status).toBe(200);
		const listJson = await list.json();
		expect(listJson.data.length).toBeGreaterThanOrEqual(8);

		const one = await app.request('/api/grievances/GRV-0003', { headers: { Cookie: cookie } });
		expect(one.status).toBe(200);
	});

	it('comments work for permitted users', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const res = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ body: 'Following up on the leak this morning.' })
		});
		expect(res.status).toBe(201);
		const json = await res.json();
		expect(json.data.body).toContain('Following up');
		expect(json.data.author.id).toBe('stu-1');
		expect(json.data.author.password_hash).toBeUndefined();

		const list = await app.request('/api/grievances/GRV-0001/comments', { headers: { Cookie: cookie } });
		const listed = await list.json();
		expect(listed.data.some((c: { id: string }) => c.id === json.data.id)).toBe(true);
	});

	it('status changes work for wardens and are forbidden for students', async () => {
		const student = await login(app, 'student@example.test', 'student123');
		const denied = await app.request('/api/grievances/GRV-0001', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: student.cookie },
			body: JSON.stringify({ status: 'Resolved' })
		});
		expect(denied.status).toBe(403);

		const warden = await login(app, 'warden@example.test', 'warden123');
		const updated = await app.request('/api/grievances/GRV-0008', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: warden.cookie },
			body: JSON.stringify({ status: 'In Progress' })
		});
		expect(updated.status).toBe(200);
		const json = await updated.json();
		expect(json.data.status).toBe('In Progress');
	});

	it('attachment metadata and storage work', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const created = await app.request('/api/grievances', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({
				title: 'Need a photo on file',
				category: 'Other',
				description: 'Filing this so I can attach a photo of the damaged locker door.'
			})
		});
		const grievance = await created.json();
		const id = grievance.data.id as string;

		const form = new FormData();
		form.append('file', new File([PNG], 'locker.png', { type: 'image/png' }));
		const uploaded = await app.request(`/api/grievances/${id}/attachments`, {
			method: 'POST',
			headers: { Cookie: cookie },
			body: form
		});
		expect(uploaded.status).toBe(201);
		const meta = await uploaded.json();
		expect(meta.data.filename).toBe('locker.png');
		expect(meta.data.contentType).toBe('image/png');
		expect(meta.data.sizeBytes).toBe(PNG.length);

		const fileRes = await app.request(`/api/attachments/${meta.data.id}`, { headers: { Cookie: cookie } });
		expect(fileRes.status).toBe(200);
		expect(fileRes.headers.get('content-type')).toBe('image/png');
		const bytes = Buffer.from(await fileRes.arrayBuffer());
		expect(bytes.equals(PNG)).toBe(true);

		const other = await login(app, 'priya@example.test', 'student123');
		const stolen = await app.request(`/api/attachments/${meta.data.id}`, {
			headers: { Cookie: other.cookie }
		});
		expect(stolen.status).toBe(403);
	});

	it('rejects oversized and disallowed attachments', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const huge = new Uint8Array(2 * 1024 * 1024 + 1);
		const over = new FormData();
		over.append('file', new File([huge], 'big.png', { type: 'image/png' }));
		const overRes = await app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie },
			body: over
		});
		expect(overRes.status).toBe(400);

		const invalid = new FormData();
		invalid.append('file', new File(['not-an-image'], 'notes.txt', { type: 'text/plain' }));
		const invalidRes = await app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie },
			body: invalid
		});
		expect(invalidRes.status).toBe(400);
	});

	it('lets a student edit their own open grievance but not a resolved one', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const edited = await app.request('/api/grievances/GRV-0008', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ title: 'Mess tables still dirty before dinner' })
		});
		expect(edited.status).toBe(200);
		const editedJson = await edited.json();
		expect(editedJson.data.title).toContain('still dirty');

		const other = await login(app, 'priya@example.test', 'student123');
		const forbidden = await app.request('/api/grievances/GRV-0008', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: other.cookie },
			body: JSON.stringify({ title: 'Should not work at all here' })
		});
		expect(forbidden.status).toBe(403);

		const rohan = await login(app, 'rohan@example.test', 'student123');
		const resolved = await app.request('/api/grievances/GRV-0004', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: rohan.cookie },
			body: JSON.stringify({ title: 'Trying to change a resolved ticket' })
		});
		expect(resolved.status).toBe(409);
		const resolvedJson = await resolved.json();
		expect(resolvedJson.code).toBe('conflict');
	});

	it('rejects unauthenticated grievance access', async () => {
		const res = await app.request('/api/grievances');
		expect(res.status).toBe(401);
	});

	it('returns 404 for unknown grievance ids without leaking internals', async () => {
		const { cookie } = await login(app, 'warden@example.test', 'warden123');
		const res = await app.request('/api/grievances/GRV-9999', { headers: { Cookie: cookie } });
		expect(res.status).toBe(404);
		const json = await res.json();
		expect(json.code).toBe('not_found');
		expect(JSON.stringify(json)).not.toMatch(/sqlite|stack|ENOENT/i);
	});
});

describe('HostelGrievance API hardening regressions', () => {
	let dir: string;
	let uploadDir: string;
	let db: Database;
	let app: ReturnType<typeof createApp>;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'hg-sec-'));
		db = openDatabase(join(dir, 'hostel.db'));
		uploadDir = join(dir, 'uploads');
		seedDatabase(db, uploadDir);
		app = createApp({ db, uploadsDir: uploadDir });
	});

	afterEach(() => {
		db.close();
		rmSync(dir, { recursive: true, force: true });
	});

	// H-01 — an uploaded filename must never influence the path written to disk.
	it('does not let an upload filename escape the uploads directory', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const before = readdirSync(uploadDir);

		const form = new FormData();
		form.append('file', new File([PNG], '../../escaped.png', { type: 'image/png' }));
		const res = await app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie },
			body: form
		});

		// The upload still succeeds — only the storage path is server-controlled.
		expect(res.status).toBe(201);
		const json = await res.json();
		// The uploader's name is preserved for display, sanitised to a basename.
		expect(json.data.filename).toBe('escaped.png');

		expect(existsSync(join(dir, 'escaped.png'))).toBe(false);
		expect(existsSync(join(dir, '..', 'escaped.png'))).toBe(false);
		const added = readdirSync(uploadDir).filter((n) => !before.includes(n));
		expect(added).toHaveLength(1);
		expect(added[0]).toMatch(/^[0-9a-f]{32}\.png$/);
	});

	// H-01 — a second upload must not be able to clobber an existing stored file.
	it('does not overwrite an existing stored file via the upload filename', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const existing = readdirSync(uploadDir)[0];
		const originalBytes = readFileSync(join(uploadDir, existing));

		const form = new FormData();
		form.append('file', new File([Buffer.from('OVERWRITTEN')], existing, { type: 'image/png' }));
		const res = await app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie },
			body: form
		});
		expect(res.status).toBe(201);
		expect(readFileSync(join(uploadDir, existing)).equals(originalBytes)).toBe(true);
	});

	// H-02 — comment endpoints are as sensitive as the grievance itself.
	it('does not let a student read or comment on another student’s grievance', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');

		const read = await app.request('/api/grievances/GRV-0003/comments', {
			headers: { Cookie: cookie }
		});
		expect(read.status).toBe(403);
		expect((await read.json()).code).toBe('unauthorized');

		const write = await app.request('/api/grievances/GRV-0003/comments', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ body: 'Should never be stored.' })
		});
		expect(write.status).toBe(403);

		// Confirm nothing was persisted, viewed through the owner's own session.
		const owner = await login(app, 'priya@example.test', 'student123');
		const asOwner = await app.request('/api/grievances/GRV-0003/comments', {
			headers: { Cookie: owner.cookie }
		});
		expect(asOwner.status).toBe(200);
		const ownerJson = await asOwner.json();
		expect(
			ownerJson.data.some((c: { body: string }) => c.body === 'Should never be stored.')
		).toBe(false);
	});

	// H-02 — the owner's own comment workflow must be unaffected.
	it('still lets the owning student and the warden use the comment workflow', async () => {
		const student = await login(app, 'student@example.test', 'student123');
		const own = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: student.cookie },
			body: JSON.stringify({ body: 'Owner comment still works.' })
		});
		expect(own.status).toBe(201);

		const warden = await login(app, 'warden@example.test', 'warden123');
		const asWarden = await app.request('/api/grievances/GRV-0003/comments', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: warden.cookie },
			body: JSON.stringify({ body: 'Warden reply on any grievance.' })
		});
		expect(asWarden.status).toBe(201);

		const wardenRead = await app.request('/api/grievances/GRV-0003/comments', {
			headers: { Cookie: warden.cookie }
		});
		expect(wardenRead.status).toBe(200);
	});

	// H-03 — attachment IDs are guessable, so the object check must be server-side.
	it('scopes attachment downloads to users authorised for the grievance', async () => {
		const student = await login(app, 'student@example.test', 'student123');
		const mine = await app.request('/api/attachments/att-1', { headers: { Cookie: student.cookie } });
		expect(mine.status).toBe(200);

		const other = await login(app, 'priya@example.test', 'student123');
		const stolen = await app.request('/api/attachments/att-1', { headers: { Cookie: other.cookie } });
		expect(stolen.status).toBe(403);
		expect((await stolen.json()).code).toBe('unauthorized');

		const warden = await login(app, 'warden@example.test', 'warden123');
		const asWarden = await app.request('/api/attachments/att-1', {
			headers: { Cookie: warden.cookie }
		});
		expect(asWarden.status).toBe(200);

		const anon = await app.request('/api/attachments/att-1');
		expect(anon.status).toBe(401);
	});

	// H-05 — expiry stored in the session row must actually be enforced.
	it('rejects a session whose stored expiry has passed', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		expect((await app.request('/api/me', { headers: { Cookie: cookie } })).status).toBe(200);

		const token = cookie.split('=').slice(1).join('=');
		db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(
			'2000-01-01T00:00:00.000Z',
			token
		);

		const after = await app.request('/api/me', { headers: { Cookie: cookie } });
		expect(after.status).toBe(401);
		const grievances = await app.request('/api/grievances', { headers: { Cookie: cookie } });
		expect(grievances.status).toBe(401);
	});

	// H-05 — logout must destroy the server-side session, not just the cookie.
	it('invalidates the server-side session on logout', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');
		const token = cookie.split('=').slice(1).join('=');
		expect(db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE token = ?').get(token).n).toBe(1);

		await app.request('/api/logout', { method: 'POST', headers: { Cookie: cookie } });

		expect(db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE token = ?').get(token).n).toBe(0);
		const replay = await app.request('/api/grievances', { headers: { Cookie: cookie } });
		expect(replay.status).toBe(401);

		// A fresh login must still work after a logout.
		const again = await login(app, 'student@example.test', 'student123');
		expect(again.res.status).toBe(200);
		expect((await app.request('/api/me', { headers: { Cookie: again.cookie } })).status).toBe(200);
	});

	// H-06 — the cookie carrying the session must not be readable by scripts.
	it('sets HttpOnly and SameSite on the session cookie', async () => {
		const res = await app.request('/api/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'student@example.test', password: 'student123' })
		});
		const raw = setCookieHeader(res);
		expect(raw).toMatch(/HttpOnly/i);
		expect(raw).toMatch(/SameSite=Lax/i);
		expect(raw).toMatch(/Path=\//);
	});

	// H-08 — status is a warden-only field, as the student UI already states.
	it('refuses student status changes but keeps student content edits working', async () => {
		const { cookie } = await login(app, 'student@example.test', 'student123');

		const before = await app.request('/api/grievances/GRV-0001', { headers: { Cookie: cookie } });
		const statusBefore = (await before.json()).data.status;
		expect(statusBefore).not.toBe('Resolved');

		const status = await app.request('/api/grievances/GRV-0001', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ status: 'Resolved' })
		});
		expect(status.status).toBe(403);
		expect((await status.json()).code).toBe('unauthorized');

		// Sending status alongside content must not smuggle the change through.
		const mixed = await app.request('/api/grievances/GRV-0001', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ title: 'Ceiling leak is worse today', status: 'Resolved' })
		});
		expect(mixed.status).toBe(403);

		const unchanged = await app.request('/api/grievances/GRV-0001', { headers: { Cookie: cookie } });
		const unchangedJson = await unchanged.json();
		expect(unchangedJson.data.status).toBe(statusBefore);
		expect(unchangedJson.data.title).not.toContain('worse today');

		// The student's own content edit still succeeds.
		const edit = await app.request('/api/grievances/GRV-0001', {
			method: 'PATCH',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ title: 'Ceiling leak is worse today' })
		});
		expect(edit.status).toBe(200);
		expect((await edit.json()).data.title).toBe('Ceiling leak is worse today');
	});
});

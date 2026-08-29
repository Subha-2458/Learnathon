
import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { requireUser } from '../auth/session.ts';
import {
	assembleGrievance,
	assertCanViewGrievance,
	findUserById,
	listAllGrievanceRows,
	listCommentRows,
	listGrievanceRowsForStudent,
	nextAttachmentId,
	nextCommentId,
	nextGrievanceId,
	requireGrievance,
	touchGrievance
} from '../db/queries.ts';
import type { CommentRow, AttachmentRow } from '../types/index.ts';
import { toPublicAttachment, toPublicComment, toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import { audit } from '../http/audit.ts';
import { parseCategory, statusToDb, assertValidTransition } from '../http/status.ts';
import {
	bufferFromUpload,
	newStoredName,
	originalBasename,
	writeStoredFile
} from '../storage/attachments.ts';

function nowIso(): string {
	return new Date().toISOString();
}

function readString(value: unknown): string | undefined {
	return typeof value === 'string' ? value : undefined;
}

export const grievanceRoutes = new Hono<AppEnv>();

const DEFAULT_PAGE_LIMIT = 20;
const MAX_PAGE_LIMIT = 100;

grievanceRoutes.get('/', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);

	// Pagination — clamp to sane bounds so no one can request unlimited rows.
	const rawLimit = Number.parseInt(c.req.query('limit') ?? '', 10);
	const rawOffset = Number.parseInt(c.req.query('offset') ?? '', 10);
	const limit = Number.isFinite(rawLimit) && rawLimit > 0
		? Math.min(rawLimit, MAX_PAGE_LIMIT)
		: DEFAULT_PAGE_LIMIT;
	const offset = Number.isFinite(rawOffset) && rawOffset > 0 ? rawOffset : 0;

	const rows =
		user.role === 'warden'
			? listAllGrievanceRows(db, limit, offset)
			: listGrievanceRowsForStudent(db, user.id, limit, offset);

	return c.json({
		data: rows.map((row) => assembleGrievance(db, row)),
		pagination: { limit, offset, count: rows.length }
	});
});

grievanceRoutes.post('/', async (c) => {
	const db = c.get('db');
	const uploadsDir = c.get('uploadsDir');
	const user = requireUser(c, db);
	if (user.role !== 'student') {
		throw new HttpError(403, 'unauthorized', 'Only students can file grievances.');
	}

	const contentType = c.req.header('content-type') ?? '';
	let title = '';
	let category = '';
	let description = '';
	let upload: File | undefined;

	if (contentType.includes('multipart/form-data')) {
		const body = await c.req.parseBody();
		title = readString(body.title) ?? '';
		category = readString(body.category) ?? '';
		description = readString(body.description) ?? '';
		if (body.file instanceof File) upload = body.file;
		else if (body.attachment instanceof File) upload = body.attachment;
	} else {
		let json: unknown;
		try {
			json = await c.req.json();
		} catch {
			throw new HttpError(400, 'bad_request', 'Request body must be JSON or multipart form data.');
		}
		if (!json || typeof json !== 'object') {
			throw new HttpError(400, 'bad_request', 'Request body must be JSON or multipart form data.');
		}
		title = readString('title' in json ? json.title : undefined) ?? '';
		category = readString('category' in json ? json.category : undefined) ?? '';
		description = readString('description' in json ? json.description : undefined) ?? '';
	}

	title = title.trim();
	description = description.trim();
	if (title.length < 5) {
		throw new HttpError(400, 'bad_request', 'Title must be at least 5 characters.');
	}
	if (description.length < 20) {
		throw new HttpError(400, 'bad_request', 'Description must be at least 20 characters.');
	}
	const parsedCategory = parseCategory(category);

	// Buffer and validate the upload BEFORE any DB work so we never write a
	// grievance row without its attachment (orphan on failure).
	let bytes: Buffer | undefined;
	let stored: string | undefined;
	if (upload) {
		bytes = await bufferFromUpload(upload);
		stored = newStoredName(upload.type);
	}

	const id = nextGrievanceId(db);
	const ts = nowIso();

	// Both inserts run in a single transaction so the grievance and its
	// attachment record are always consistent.
	try {
		db.transaction(() => {
			db.prepare(
				`INSERT INTO grievances (id, student_id, title, category, description, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`
			).run(id, user.id, title, parsedCategory, description, ts, ts);

			if (upload && bytes && stored) {
				db.prepare(
					`INSERT INTO attachments (id, grievance_id, original_filename, stored_filename, mime_type, size_bytes, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
				).run(
					nextAttachmentId(db),
					id,
					originalBasename(upload.name),
					stored,
					upload.type,
					bytes.byteLength,
					ts
				);
			}
		})();
	} catch (err) {
		// If the transaction failed, nothing was written to the DB.
		throw err;
	}

	// Write the file to disk AFTER the DB transaction succeeds.  If the file
	// write fails we roll back the DB rows we just committed.
	try {
		if (upload && bytes && stored) {
			writeStoredFile(uploadsDir, stored, bytes);
		}
	} catch (fileErr) {
		// Clean up the DB rows that were just committed.
		db.prepare('DELETE FROM attachments WHERE grievance_id = ?').run(id);
		db.prepare('DELETE FROM grievances WHERE id = ?').run(id);
		throw fileErr;
	}

	return c.json({ data: assembleGrievance(db, requireGrievance(db, id)) }, 201);
});

grievanceRoutes.get('/:id/comments', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	const row = requireGrievance(db, c.req.param('id'));
	assertCanViewGrievance(user, row);
	const comments = listCommentRows(db, row.id).map((comment) => {
		const authorRow = findUserById(db, comment.author_id);
		if (!authorRow) {
			throw new HttpError(500, 'internal', 'Internal server error.');
		}
		return toPublicComment(comment, toPublicUser(authorRow));
	});
	return c.json({ data: comments });
});

grievanceRoutes.post('/:id/comments', async (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	const row = requireGrievance(db, c.req.param('id'));
	assertCanViewGrievance(user, row);

	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		throw new HttpError(400, 'bad_request', 'JSON body is required.');
	}
	const text =
		body && typeof body === 'object' && 'body' in body && typeof body.body === 'string'
			? body.body.trim()
			: '';
	if (!text) {
		throw new HttpError(400, 'bad_request', 'Comment cannot be empty.');
	}
	if (text.length > 5000) {
		throw new HttpError(400, 'bad_request', 'Comment must be at most 5000 characters.');
	}

	const id = nextCommentId(db);
	const ts = nowIso();
	db.prepare(
		`INSERT INTO comments (id, grievance_id, author_id, body, created_at) VALUES (?, ?, ?, ?, ?)`
	).run(id, row.id, user.id, text, ts);
	touchGrievance(db, row.id, ts);

	const author = findUserById(db, user.id);
	if (!author) {
		throw new HttpError(500, 'internal', 'Internal server error.');
	}
	const commentRow = db.prepare('SELECT * FROM comments WHERE id = ?').get(id) as CommentRow;
	return c.json({ data: toPublicComment(commentRow, toPublicUser(author)) }, 201);
});

grievanceRoutes.post('/:id/attachments', async (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	const row = requireGrievance(db, c.req.param('id'));
	if (user.role !== 'student' || row.student_id !== user.id) {
		throw new HttpError(403, 'unauthorized', 'Only the student owner can add attachments.');
	}
	if (row.status === 'resolved') {
		throw new HttpError(409, 'conflict', 'Resolved grievances cannot be edited.');
	}

	const body = await c.req.parseBody();
	const upload = body.file instanceof File ? body.file : body.attachment instanceof File ? body.attachment : undefined;
	if (!upload) {
		throw new HttpError(400, 'bad_request', 'A file field named file is required.');
	}

	const bytes = await bufferFromUpload(upload);
	const stored = newStoredName(upload.type);
	const ts = nowIso();
	writeStoredFile(c.get('uploadsDir'), stored, bytes);
	const id = nextAttachmentId(db);
	db.prepare(
		`INSERT INTO attachments (id, grievance_id, original_filename, stored_filename, mime_type, size_bytes, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
	).run(id, row.id, originalBasename(upload.name), stored, upload.type, bytes.byteLength, ts);
	touchGrievance(db, row.id, ts);
	const saved = db.prepare('SELECT * FROM attachments WHERE id = ?').get(id) as AttachmentRow;
	return c.json({ data: toPublicAttachment(saved) }, 201);
});

grievanceRoutes.get('/:id', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	const row = requireGrievance(db, c.req.param('id'));
	assertCanViewGrievance(user, row);
	return c.json({ data: assembleGrievance(db, row) });
});

grievanceRoutes.patch('/:id', async (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	const row = requireGrievance(db, c.req.param('id'));
	assertCanViewGrievance(user, row);

	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	if (!body || typeof body !== 'object') {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}

	const title = 'title' in body ? body.title : undefined;
	const description = 'description' in body ? body.description : undefined;
	const category = 'category' in body ? body.category : undefined;
	const status = 'status' in body ? body.status : undefined;
	const wantsContent = title !== undefined || description !== undefined || category !== undefined;
	const wantsStatus = status !== undefined;

	if (!wantsContent && !wantsStatus) {
		throw new HttpError(400, 'bad_request', 'No updatable fields were provided.');
	}

	switch (user.role) {
		case 'student': {
			// Status transitions are the warden's alone. Checked before the resolved
			// check so an unauthorised field is rejected on its own merits rather
			// than depending on the grievance's current state.
			if (wantsStatus) {
				throw new HttpError(
					403,
					'unauthorized',
					'Only the warden can change the status of a grievance.'
				);
			}
			if (row.status === 'resolved') {
				throw new HttpError(409, 'conflict', 'Resolved grievances cannot be edited.');
			}
			let nextTitle = row.title;
			let nextDescription = row.description;
			let nextCategory = row.category;
			if (title !== undefined) {
				if (typeof title !== 'string' || title.trim().length < 5) {
					throw new HttpError(400, 'bad_request', 'Title must be at least 5 characters.');
				}
				nextTitle = title.trim();
			}
			if (description !== undefined) {
				if (typeof description !== 'string' || description.trim().length < 20) {
					throw new HttpError(400, 'bad_request', 'Description must be at least 20 characters.');
				}
				nextDescription = description.trim();
			}
			if (category !== undefined) {
				if (typeof category !== 'string') {
					throw new HttpError(400, 'bad_request', 'Invalid grievance category.');
				}
				nextCategory = parseCategory(category);
			}
			const ts = nowIso();
			db.prepare(
				'UPDATE grievances SET title = ?, description = ?, category = ?, updated_at = ? WHERE id = ?'
			).run(nextTitle, nextDescription, nextCategory, ts, row.id);
			break;
		}
		case 'warden': {
			if (wantsContent) {
				throw new HttpError(403, 'unauthorized', 'Wardens cannot edit grievance content.');
			}
			if (typeof status !== 'string') {
				throw new HttpError(400, 'bad_request', 'Invalid grievance status.');
			}
		const nextStatus = statusToDb(status);
		assertValidTransition(row.status, nextStatus);
		const ts = nowIso();
			db.prepare('UPDATE grievances SET status = ?, updated_at = ? WHERE id = ?').run(
				nextStatus,
				ts,
				row.id
			);
		audit({
			ts: new Date().toISOString(),
			event: 'status_change',
			userId: user.id,
			resource: row.id,
			detail: `${row.status} → ${nextStatus}`
		});
			break;
		}
		default: {
			const _exhaustive: never = user.role;
			throw new HttpError(500, 'internal', 'Internal server error.');
			void _exhaustive;
		}
	}

	return c.json({ data: assembleGrievance(db, requireGrievance(db, row.id)) });
});

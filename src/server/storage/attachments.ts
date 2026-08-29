import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ALLOWED_ATTACHMENT_TYPES, MAX_ATTACHMENT_BYTES } from '../config.ts';
import { HttpError } from '../http/errors.ts';

const MIME_EXTENSION: Record<string, string> = {
	'image/jpeg': '.jpg',
	'image/png': '.png',
	'image/gif': '.gif',
	'image/webp': '.webp'
};

export function ensureUploadsDir(dir: string): void {
	mkdirSync(dir, { recursive: true });
}

export function resetUploadsDir(dir: string): void {
	if (existsSync(dir)) {
		rmSync(dir, { recursive: true, force: true });
	}
	mkdirSync(dir, { recursive: true });
}

export function originalBasename(filename: string): string {
	const base = filename.replace(/\\/g, '/').split('/').pop() ?? 'upload';
	const cleaned = base.replace(/[\0\r\n]/g, '').trim();
	return cleaned.length > 0 ? cleaned.slice(0, 255) : 'upload';
}

export function extensionForMime(mime: string): string {
	return MIME_EXTENSION[mime] ?? '.bin';
}

/**
 * Stored names are always server-generated. The uploader's filename is kept
 * separately as `original_filename` for display and never used as a path.
 */
export function newStoredName(mime: string): string {
	return `${randomBytes(16).toString('hex')}${extensionForMime(mime)}`;
}

/**
 * Resolve a stored attachment name to an absolute path that is guaranteed to
 * sit directly inside `uploadsDir`. Returns undefined when the name is not a
 * plain filename or escapes the directory; callers map that to their own error.
 */
function resolveInsideUploads(uploadsDir: string, storedName: string): string | undefined {
	if (
		!storedName ||
		storedName.includes('/') ||
		storedName.includes('\\') ||
		storedName.includes('..')
	) {
		return undefined;
	}
	const root = resolve(uploadsDir);
	const full = resolve(join(uploadsDir, storedName));
	if (full === root || !full.startsWith(root + sep)) {
		return undefined;
	}
	return full;
}

export function assertPermittedAttachment(mime: string, size: number): void {
	if (!ALLOWED_ATTACHMENT_TYPES.has(mime)) {
		throw new HttpError(400, 'bad_request', 'Attachments must be JPEG, PNG, GIF, or WebP images.');
	}
	if (size <= 0) {
		throw new HttpError(400, 'bad_request', 'Attachment file is empty.');
	}
	if (size > MAX_ATTACHMENT_BYTES) {
		throw new HttpError(400, 'bad_request', 'Attachment must be 2 MB or smaller.');
	}
}

/**
 * Verify that the file's actual bytes match the declared MIME type by
 * inspecting magic-byte signatures.  This catches Content-Type spoofing:
 * a request that claims image/png but contains a PDF will be rejected.
 */
function assertMagicBytesMatch(bytes: Buffer, mime: string): void {
	if (bytes.length < 12) {
		throw new HttpError(400, 'bad_request', 'File is too small to identify.');
	}

	let detected: string | undefined;

	// JPEG: starts with FF D8 FF
	if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
		detected = 'image/jpeg';
	}
	// PNG: starts with 89 50 4e 47 0d 0a 1a 0a (\x89PNG\r\n\x1a\n)
	else if (
		bytes[0] === 0x89 &&
		bytes[1] === 0x50 &&
		bytes[2] === 0x4e &&
		bytes[3] === 0x47
	) {
		detected = 'image/png';
	}
	// GIF: starts with GIF8 (GIF87a or GIF89a)
	else if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
		detected = 'image/gif';
	}
	// WebP: RIFF header (52 49 46 46) with WEBP at offset 8
	else if (
		bytes[0] === 0x52 &&
		bytes[1] === 0x49 &&
		bytes[2] === 0x46 &&
		bytes[3] === 0x46 &&
		bytes[8] === 0x57 &&
		bytes[9] === 0x45 &&
		bytes[10] === 0x42 &&
		bytes[11] === 0x50
	) {
		detected = 'image/webp';
	}

	if (!detected) {
		throw new HttpError(400, 'bad_request', 'File content does not match the declared image type.');
	}
	if (detected !== mime) {
		throw new HttpError(
			400,
			'bad_request',
			`File content is ${detected} but the declared type is ${mime}.`
		);
	}
}

export async function bufferFromUpload(file: File): Promise<Buffer> {
	const bytes = Buffer.from(await file.arrayBuffer());
	assertPermittedAttachment(file.type, bytes.byteLength);
	assertMagicBytesMatch(bytes, file.type);
	return bytes;
}

export function writeStoredFile(uploadsDir: string, storedName: string, bytes: Buffer): void {
	ensureUploadsDir(uploadsDir);
	const full = resolveInsideUploads(uploadsDir, storedName);
	if (!full) {
		throw new HttpError(400, 'bad_request', 'Attachment could not be stored.');
	}
	// 'wx' fails instead of overwriting, so a stored name can never clobber an
	// existing file.
	writeFileSync(full, bytes, { flag: 'wx' });
}

export function readStoredFile(uploadsDir: string, storedName: string): Buffer {
	const full = resolveInsideUploads(uploadsDir, storedName);
	if (!full || !existsSync(full)) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	return readFileSync(full);
}

export function listStoredNames(uploadsDir: string): string[] {
	if (!existsSync(uploadsDir)) return [];
	return readdirSync(uploadsDir).filter((name) => name !== '.gitkeep');
}

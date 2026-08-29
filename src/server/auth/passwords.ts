import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SCRYPT_KEY_LENGTH = 64;
const SCRYPT_COST = 16384;
const SCRYPT_BLOCK_SIZE = 8;
const SCRYPT_PARALLELIZATION = 1;

/**
 * Hash a password using scrypt with a random 16-byte salt.
 * Format: scrypt:<salt_hex>:<hash_hex>
 */
export function hashPassword(password: string): string {
	const salt = randomBytes(16);
	const hash = scryptSync(password, salt, SCRYPT_KEY_LENGTH, {
		N: SCRYPT_COST,
		r: SCRYPT_BLOCK_SIZE,
		p: SCRYPT_PARALLELIZATION
	});
	return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;
}

/**
 * Verify a password against a stored hash.
 * Supports both the current scrypt scheme and the legacy sha256 scheme.
 * Returns { ok, needsMigration } so the caller can re-hash legacy passwords.
 */
export function verifyPassword(
	password: string,
	stored: string
): { ok: boolean; needsMigration: boolean } {
	const parts = stored.split(':');
	if (parts.length < 2) return { ok: false, needsMigration: false };

	const [scheme] = parts;

	if (scheme === 'scrypt' && parts.length === 3) {
		const salt = Buffer.from(parts[1], 'hex');
		const expected = Buffer.from(parts[2], 'hex');
		const actual = scryptSync(password, salt, SCRYPT_KEY_LENGTH, {
			N: SCRYPT_COST,
			r: SCRYPT_BLOCK_SIZE,
			p: SCRYPT_PARALLELIZATION
		});
		if (actual.length !== expected.length) return { ok: false, needsMigration: false };
		const matches = timingSafeEqual(actual, expected);
		return { ok: matches, needsMigration: false };
	}

	// Legacy sha256:<hex> scheme
	if (scheme === 'sha256' && parts.length === 2) {
		const hash = parts[1];
		const actual = createHash('sha256').update(password).digest();
		const expected = Buffer.from(hash, 'hex');
		if (actual.length !== expected.length) return { ok: false, needsMigration: false };
		const matches = timingSafeEqual(actual, expected);
		return { ok: matches, needsMigration: matches }; // successful legacy → migrate
	}

	return { ok: false, needsMigration: false };
}

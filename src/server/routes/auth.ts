import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import {
	createSession,
	clearSessionCookie,
	destroySession,
	optionalToken,
	requireUser,
	setSessionCookie
} from '../auth/session.ts';
import { hashPassword, verifyPassword } from '../auth/passwords.ts';
import { findUserByEmail } from '../db/queries.ts';
import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import { RateLimiter } from '../http/rate-limit.ts';
import { audit } from '../http/audit.ts';

/** Max 10 failed login attempts per IP per 15-minute window. */
const loginLimiter = new RateLimiter({ max: 10, windowMs: 15 * 60 * 1000 });

function clientIp(c: { req: { header(name: string): string | undefined } }): string {
	return c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? '127.0.0.1';
}

export const authRoutes = new Hono<AppEnv>();

authRoutes.post('/login', async (c) => {
	const db = c.get('db');
	const ip = clientIp(c);

	// Rate-limit failed login attempts per IP.
	const check = loginLimiter.touch(ip);
	if (check.limited) {
		audit({ ts: new Date().toISOString(), event: 'login_rate_limited', ip });
		throw new HttpError(429, 'too_many_requests', 'Too many login attempts. Please try again later.');
	}

	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	if (!body || typeof body !== 'object') {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	const email = 'email' in body && typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
	const password = 'password' in body && typeof body.password === 'string' ? body.password : '';
	if (!email || !password) {
		throw new HttpError(400, 'bad_request', 'Email and password are required.');
	}
	const user = findUserByEmail(db, email);
	// Always run verifyPassword to prevent timing-based user enumeration.
	// For non-existent emails, use a dummy hash so scrypt still runs.
	const dummyHash = 'scrypt:00000000000000000000000000000000:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
	const result = verifyPassword(password, user ? user.password_hash : dummyHash);
	if (!user || !result.ok) {
		audit({ ts: new Date().toISOString(), event: 'login_failure', ip, detail: email });
		throw new HttpError(401, 'unauthenticated', 'Invalid email or password.');
	}
	// Successful login — reset the rate limiter for this IP.
	loginLimiter.reset(ip);
	audit({ ts: new Date().toISOString(), event: 'login_success', userId: user.id, ip });
	// Upgrade legacy sha256 hashes to scrypt on successful login.
	if (result.needsMigration) {
		const freshHash = hashPassword(password);
		db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(freshHash, user.id);
	}
	// Invalidate all existing sessions for this user to prevent session
	// accumulation and ensure a compromised token cannot be reused.
	db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
	// Also clean up expired sessions for all users to prevent table bloat.
	db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());
	const token = createSession(db, user.id);
	setSessionCookie(c, token);
	return c.json({ user: toPublicUser(user) });
});	authRoutes.post('/logout', (c) => {
	const token = optionalToken(c);
	if (token) {
		// Clearing the cookie alone leaves the session usable by anyone who still
		// holds the token, so the server-side record has to go too.
		destroySession(c.get('db'), token);
		audit({ ts: new Date().toISOString(), event: 'logout' });
	}
	clearSessionCookie(c);
	return c.json({ ok: true });
});

authRoutes.get('/me', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	return c.json({ user: toPublicUser(user) });
});

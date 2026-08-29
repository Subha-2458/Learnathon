import type { MiddlewareHandler } from 'hono';

/**
 * Adds common security headers to every API response.
 * Lightweight, zero-dependency — just sets headers.
 */
export const securityHeaders: MiddlewareHandler = async (c, next) => {
	await next();

	// Prevent MIME sniffing — browsers must respect the declared Content-Type.
	c.header('X-Content-Type-Options', 'nosniff');

	// Prevent the app from being embedded in an iframe (clickjacking).
	c.header('X-Frame-Options', 'DENY');

	// Control how much referrer information is sent.
	c.header('Referrer-Policy', 'strict-origin-when-cross-origin');

	// Prevent browsers from caching sensitive API responses.
	c.header('Cache-Control', 'no-store, no-cache, must-revalidate');
	c.header('Pragma', 'no-cache');
};

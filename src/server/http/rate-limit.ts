/**
 * Simple in-memory sliding-window rate limiter.
 *
 * Designed for a single-process Node server. Each key (typically the client IP)
 * is tracked independently. Entries that have not been touched within the window
 * are lazily evicted to prevent unbounded memory growth.
 */

export interface RateLimiterOptions {
	/** Maximum number of hits allowed within the window. Default: 5 */
	max: number;
	/** Window length in milliseconds. Default: 15 minutes */
	windowMs: number;
}

interface Bucket {
	hits: number;
	windowStart: number;
}

export class RateLimiter {
	private readonly max: number;
	private readonly windowMs: number;
	private readonly buckets = new Map<string, Bucket>();

	constructor(options: RateLimiterOptions) {
		this.max = options.max;
		this.windowMs = options.windowMs;
	}

	/**
	 * Record one hit for the given key.
	 * Returns { limited: true, retryAfterMs } when the key has exceeded the
	 * allowed number of hits within the current window.
	 */
	touch(key: string): { limited: boolean; retryAfterMs: number } {
		const now = Date.now();
		const bucket = this.buckets.get(key);

		if (!bucket || now - bucket.windowStart > this.windowMs) {
			// New window
			this.buckets.set(key, { hits: 1, windowStart: now });
			return { limited: false, retryAfterMs: 0 };
		}

		bucket.hits += 1;
		if (bucket.hits > this.max) {
			const retryAfterMs = this.windowMs - (now - bucket.windowStart);
			return { limited: true, retryAfterMs };
		}

		return { limited: false, retryAfterMs: 0 };
	}

	/** Reset the counter for a specific key (e.g. after a successful login). */
	reset(key: string): void {
		this.buckets.delete(key);
	}

	/** Remove expired entries (call periodically to bound memory). */
	prune(): void {
		const now = Date.now();
		for (const [key, bucket] of this.buckets) {
			if (now - bucket.windowStart > this.windowMs) {
				this.buckets.delete(key);
			}
		}
	}
}

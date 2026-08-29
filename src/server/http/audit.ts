/**
 * Structured audit logger for security-relevant events.
 *
 * Writes JSON lines to stdout so they can be collected by any log shipper.
 * In production, pipe stdout to a file or aggregate with journald / CloudWatch.
 * No dependencies — uses console.info which writes to process.stdout.
 */

export type AuditEvent =
	| 'login_success'
	| 'login_failure'
	| 'login_rate_limited'
	| 'logout'
	| 'session_expired'
	| 'unauthorized_access'
	| 'status_change'
	| 'grievance_created'
	| 'attachment_uploaded'
	| 'attachment_downloaded';

export interface AuditEntry {
	ts: string;
	event: AuditEvent;
	userId?: string;
	ip?: string;
	resource?: string;
	detail?: string;
}

/**
 * Write a structured audit event.  The JSON line is safe to parse and
 * index — no user-controlled content is interpolated into the format string.
 */
export function audit(entry: AuditEntry): void {
	console.info(JSON.stringify(entry));
}

import { HttpError } from './errors.ts';
import type { GrievanceCategory, GrievanceStatusDb, GrievanceStatusUi } from '../types/index.ts';

export const GRIEVANCE_CATEGORIES: readonly GrievanceCategory[] = [
	'Maintenance',
	'Water',
	'Electricity',
	'Internet',
	'Cleanliness',
	'Room',
	'Other'
];

export function statusToUi(status: GrievanceStatusDb): GrievanceStatusUi {
	switch (status) {
		case 'open':
			return 'Open';
		case 'in_progress':
			return 'In Progress';
		case 'resolved':
			return 'Resolved';
		default: {
			const _exhaustive: never = status;
			return _exhaustive;
		}
	}
}

export function statusToDb(status: string): GrievanceStatusDb {
	switch (status) {
		case 'open':
		case 'Open':
			return 'open';
		case 'in_progress':
		case 'In Progress':
			return 'in_progress';
		case 'resolved':
		case 'Resolved':
			return 'resolved';
		default:
			throw new HttpError(400, 'bad_request', 'Invalid grievance status.');
	}
}

/**
 * Enforce valid grievance status transitions.
 *
 * Allowed:
 *   open → in_progress   (warden starts work)
 *   in_progress → resolved   (warden resolves)
 *   in_progress → open   (warden reopens)
 *   resolved → open   (reopen after resolution)
 *
 * Forbidden:
 *   open → resolved   (skip acknowledgment)
 *   resolved → in_progress   (must reopen first)
 */
const VALID_TRANSITIONS: Record<GrievanceStatusDb, GrievanceStatusDb[]> = {
	open: ['in_progress'],
	in_progress: ['open', 'resolved'],
	resolved: ['open']
};

export function assertValidTransition(current: GrievanceStatusDb, next: GrievanceStatusDb): void {
	const allowed = VALID_TRANSITIONS[current];
	if (!allowed || !allowed.includes(next)) {
		throw new HttpError(
			409,
			'conflict',
			`Cannot transition grievance from "${current}" to "${next}".`
		);
	}
}

export function parseCategory(value: string): GrievanceCategory {
	if ((GRIEVANCE_CATEGORIES as readonly string[]).includes(value)) {
		return value as GrievanceCategory;
	}
	throw new HttpError(400, 'bad_request', 'Invalid grievance category.');
}

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'svelte/compiler';
import { describe, expect, it } from 'vitest';

const componentPath = fileURLToPath(new URL('./comment-timeline.svelte', import.meta.url));

type AstNode = { type?: unknown; [key: string]: unknown };

/** Collect every node of a given `type` inside a parsed Svelte template. */
function collect(root: unknown, type: string): AstNode[] {
	const found: AstNode[] = [];
	const seen = new Set<unknown>();
	(function walk(node: unknown): void {
		if (!node || typeof node !== 'object' || seen.has(node)) return;
		seen.add(node);
		if (Array.isArray(node)) {
			node.forEach(walk);
			return;
		}
		const record = node as AstNode;
		if (record.type === type) found.push(record);
		for (const [key, value] of Object.entries(record)) {
			if (key === 'parent') continue;
			walk(value);
		}
	})(root);
	return found;
}

describe('comment-timeline template escaping', () => {
	const fragment = parse(readFileSync(componentPath, 'utf8'), { modern: true }).fragment;

	// H-04 — comment bodies are attacker-supplied and stored verbatim, so they
	// must never be interpolated as raw markup.
	it('never renders any part of a comment as raw HTML', () => {
		expect(collect(fragment, 'HtmlTag')).toEqual([]);
	});

	// Guards the fix from being "passed" by dropping the comment body entirely:
	// the body must still be rendered, just through an escaping expression tag.
	it('still renders the comment body through an escaped expression', () => {
		const bodyTags = collect(fragment, 'ExpressionTag').filter((tag) => {
			const expression = tag.expression as AstNode | undefined;
			if (!expression || expression.type !== 'MemberExpression') return false;
			const object = expression.object as AstNode | undefined;
			const property = expression.property as AstNode | undefined;
			return object?.name === 'comment' && property?.name === 'body';
		});
		expect(bodyTags).toHaveLength(1);
	});
});

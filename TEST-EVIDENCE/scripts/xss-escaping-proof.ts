/**
 * H-04 escaping proof — compiles the comment timeline component twice and
 * prints the generated server-render line for the comment body:
 *
 *   - as the file stands now (fixed)
 *   - with `{@html comment.body}` reintroduced (the original vulnerability)
 *
 * This shows the difference at the compiler level rather than asserting it:
 * `$.escape(...)` HTML-escapes the value, `$.html(...)` injects it as markup.
 *
 * Usage (from the repository root):
 *   node TEST-EVIDENCE/scripts/xss-escaping-proof.ts
 *
 * Read-only: it never writes to the component.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { compile } from 'svelte/compiler';

const componentPath = fileURLToPath(
	new URL('../../src/lib/components/app/comment-timeline.svelte', import.meta.url)
);
const source = readFileSync(componentPath, 'utf8');

/** The generated SSR lines that mention the comment body. */
function emittedFor(templateSource: string): string[] {
	return compile(templateSource, { generate: 'server', name: 'CommentTimeline' })
		.js.code.split('\n')
		.filter((line) => line.includes('comment.body'))
		.map((line) => line.trim());
}

const fixed = emittedFor(source);
const vulnerable = emittedFor(source.replace('{comment.body}', '{@html comment.body}'));

console.log('FIXED   ->', JSON.stringify(fixed));
console.log('VULN    ->', JSON.stringify(vulnerable));

const fixedEscapes = fixed.some((l) => l.includes('$.escape(comment.body)'));
const fixedHasNoHtml = !fixed.some((l) => l.includes('$.html('));
const vulnerableUsesHtml = vulnerable.some((l) => l.includes('$.html(comment.body)'));

console.log(`\nfixed emits $.escape(comment.body):        ${fixedEscapes}`);
console.log(`fixed emits no $.html(:                    ${fixedHasNoHtml}`);
console.log(`reintroduced {@html} emits $.html(...):    ${vulnerableUsesHtml}`);

const ok = fixedEscapes && fixedHasNoHtml && vulnerableUsesHtml;
console.log(ok ? '\nESCAPING CONFIRMED' : '\nESCAPING NOT CONFIRMED');
process.exit(ok ? 0 : 1);

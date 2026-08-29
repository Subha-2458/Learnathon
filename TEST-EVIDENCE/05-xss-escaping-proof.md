# 05 — XSS escaping proof (H-04)

The H-04 fix is a single-token change: `{@html comment.body}` became `{comment.body}` in
`src/lib/components/app/comment-timeline.svelte`. This is the evidence that the change does
what it claims, taken at the compiler level rather than inferred from the source.

The script compiles the component twice with `generate: 'server'` — once as the file stands,
once with `{@html}` reintroduced in memory — and prints the generated line that renders the
comment body. The component file is never written to. Unedited output:
[`raw/xss-escaping-proof.log`](raw/xss-escaping-proof.log).

```
$ node TEST-EVIDENCE/scripts/xss-escaping-proof.ts

FIXED   -> ["$$renderer.push(`<!--]--></div> <div class=\"min-w-0 flex-1 pb-6\"><div class=\"flex flex-wrap items-baseline gap-x-2\"><span class=\"text-sm font-medium\">${$.escape(comment.author.name)}</span> <span class=\"text-muted-foreground text-xs capitalize\">${$.escape(comment.author.role)}</span> <span class=\"text-muted-foreground text-xs\">· ${$.escape(formatTimestamp(comment.createdAt))}</span></div> <p class=\"mt-1 text-sm whitespace-pre-line\">${$.escape(comment.body)}</p></div></li>`);"]
VULN    -> ["$$renderer.push(`<!--]--></div> <div class=\"min-w-0 flex-1 pb-6\"><div class=\"flex flex-wrap items-baseline gap-x-2\"><span class=\"text-sm font-medium\">${$.escape(comment.author.name)}</span> <span class=\"text-muted-foreground text-xs capitalize\">${$.escape(comment.author.role)}</span> <span class=\"text-muted-foreground text-xs\">· ${$.escape(formatTimestamp(comment.createdAt))}</span></div> <p class=\"mt-1 text-sm whitespace-pre-line\">${$.html(comment.body)}</p></div></li>`);"]

fixed emits $.escape(comment.body):        true
fixed emits no $.html(:                    true
reintroduced {@html} emits $.html(...):    true

ESCAPING CONFIRMED
exit=0
```

## Reading the output

The two emissions are byte-identical except for one call:

| Variant | Emitted for the comment body |
| --- | --- |
| Fixed (current) | `${$.escape(comment.body)}` |
| Vulnerable (original) | `${$.html(comment.body)}` |

`$.escape` HTML-escapes the value; `$.html` injects it as markup. That single call is the
whole vulnerability and the whole fix.

## Why this is the right layer

Three things are visible in the same emitted line:

1. **The body now takes the same path its siblings already took.** `comment.author.name`,
   `comment.author.role`, and the formatted timestamp were already going through
   `$.escape`. The comment body was the sole exception in the element.

2. **Nothing else about the element changed.** Same `<p>`, same
   `class="mt-1 text-sm whitespace-pre-line"`, same position in the same `<div>`. The
   rendered appearance of legitimate comment text is unchanged, and newlines are still
   preserved by the pre-existing `whitespace-pre-line` class rather than by markup.

3. **The escaping is Svelte's, not hand-rolled.** No sanitizer was added, no dependency was
   introduced, and there is no allowlist to get wrong.

## Relationship to the committed tests

The two committed tests in `src/lib/components/app/comment-timeline.test.ts` assert this
same property structurally, by parsing the template and checking that no `HtmlTag` node
exists and that the body is still rendered through an escaping `ExpressionTag`.

That guard was negative-controlled during implementation: `{@html comment.body}` was
temporarily reintroduced, both tests failed, and the change was reverted immediately. This
script is the non-mutating equivalent of that control — it exercises the vulnerable variant
entirely in memory, so the negative control can be re-run at any time without editing
application code.

## Residual risk

This fix is at the render boundary, which neutralises every comment body wherever the
timeline displays it — including bodies already stored in the database. It does **not**
sanitize stored data. Comment rows still contain whatever markup was submitted, so any
future consumer that renders them as HTML would reintroduce the vulnerability. This is
carried in [`../HARDENING.md`](../HARDENING.md) as a documented residual risk.

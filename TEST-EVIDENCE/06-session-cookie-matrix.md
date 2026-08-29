# 06 — Session cookie `Secure` matrix (H-06)

`H-06` added `HttpOnly`, `SameSite=Lax`, and `Secure` to the session cookie. `HttpOnly` and
`SameSite` are unconditional. `Secure` cannot be, because the application's documented
development model serves the UI over plain HTTP at `http://localhost:5173` — a `Secure`
cookie is dropped there, which would break login for every developer.

The flag is therefore resolved by `SESSION_COOKIE_SECURE` in `src/server/config.ts`:
`NODE_ENV === 'production'` by default, overridable in either direction with
`HOSTEL_COOKIE_SECURE`.

```
$ node TEST-EVIDENCE/scripts/session-cookie-matrix.ts

OK   NODE_ENV=(unset) HOSTEL_COOKIE_SECURE=(unset) -> secure=false   (local development over plain HTTP)
OK   NODE_ENV=production HOSTEL_COOKIE_SECURE=(unset) -> secure=true   (production default)
OK   NODE_ENV=production HOSTEL_COOKIE_SECURE=false -> secure=false   (explicit opt-out wins over NODE_ENV)
OK   NODE_ENV=(unset) HOSTEL_COOKIE_SECURE=true -> secure=true   (explicit opt-in for HTTPS without NODE_ENV)

MATRIX AS DOCUMENTED
exit=0
```

Each case is resolved in a child process with a clean environment, so an inherited
`NODE_ENV` cannot skew a result. Unedited output:
[`raw/session-cookie-matrix.log`](raw/session-cookie-matrix.log).

## Deployment requirement

**`Secure` is not automatic. It is keyed to configuration, and a misconfigured deployment
silently omits it.**

| Deployment | Required setting | Resulting cookie |
| --- | --- | --- |
| Local development (`npm run dev:all`, plain HTTP) | none — leave both unset | `HttpOnly; SameSite=Lax`, no `Secure` |
| Production over HTTPS | `NODE_ENV=production` | `HttpOnly; SameSite=Lax; Secure` |
| HTTPS without `NODE_ENV=production` | `HOSTEL_COOKIE_SECURE=true` | `HttpOnly; SameSite=Lax; Secure` |

The failure mode to watch for: **serving over HTTPS without setting `NODE_ENV=production`
or `HOSTEL_COOKIE_SECURE=true`.** `SESSION_COOKIE_SECURE` resolves to `false`, the cookie
ships without `Secure`, and the session token becomes vulnerable to interception on any
downgraded or plain-HTTP request to the same host. Row 3 of the matrix above is the
supported way to fix that without changing `NODE_ENV`.

`HOSTEL_COOKIE_SECURE=false` exists so a deployment with an unusual model (for example a
trusted-network HTTP deployment) can opt out deliberately rather than by omission. It
overrides `NODE_ENV=production`, as row 3 of the run shows, so it should be set only with
intent.

## What the attribute values are, and why

| Attribute | Value | Reason |
| --- | --- | --- |
| `HttpOnly` | always on | Keeps the token out of reach of page scripts. This is the control that limits the blast radius of any future DOM XSS — it is why H-04 and H-06 were fixed as a pair. |
| `SameSite` | `Lax` | Stops cross-site requests from carrying the session. `Strict` was rejected because it would break normal top-level navigation into the app from an external link, which is a functional regression. |
| `Secure` | environment-gated | Required over HTTPS; must be off for the plain-HTTP localhost dev server. |
| `Path` | `/` | Unchanged from the original implementation. |
| `Max-Age` | `604800` (`SESSION_TTL_SECONDS`) | Unchanged from the original implementation. |

`clearSessionCookie` was updated to send the same `httpOnly`, `sameSite`, and `secure`
attributes as `setSessionCookie`. A deletion whose attributes do not match the cookie that
was set can leave the browser holding the original, which would have undermined the H-05
logout fix from the client side.

## Cross-references

- The dev-mode `Set-Cookie` header captured from a real login is in
  [`04-workflow-verification.md`](04-workflow-verification.md).
- The committed regression test `sets HttpOnly and SameSite on the session cookie` asserts
  the unconditional attributes; see [`01-test-suite.md`](01-test-suite.md). It intentionally
  does not assert on `Secure`, because that value is environment-dependent and this matrix
  is what covers it.

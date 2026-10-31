# Pack: Auth and sessions

Applies to authentication, session management, authorization, tenancy, and the middleware/policy layer.

The dominant real-world failure here is not weak crypto — it is **authorization decided in the wrong layer**, so one path out of twenty misses it. Hunt siblings, not algorithms.

## Object-level authorization (IDOR / BOLA) — check first

**Invariant:** every read and write is scoped to the caller's own subject or tenant *in the query*.

- Grep every handler that takes an id from the client: `params.id`, `params.slug`, `req.query.id`, `input.id`, `findUnique({where:{id}})`, `get_object_or_404(Model, pk=...)`, `Model.objects.get(pk=...)`.
- The finding is `findUnique({ where: { id } })` with no owner/tenant predicate. Correct shape: `where: { id, tenantId: session.tenantId }` — or a policy layer that provably injects it.
- Sibling check: list endpoint scoped, detail endpoint not; detail scoped, `PATCH`/`DELETE` not; REST scoped, GraphQL resolver not; UI scoped, export/report endpoint not.
- Indirection defeats naive scoping: nested ids (`/orgs/:orgId/projects/:projectId`), slugs, numeric ids from `next` values, file ids in download links, invoice numbers, webhook redelivery by id.
- Subscription/report/email endpoints are the classic unguarded set — they take an id and are added late.

**Tenant isolation at the data layer** is the only durable control: Postgres RLS with a session variable, or a repository layer that requires a tenant argument (type-level, no default). If the code relies on "every developer remembers `where tenantId`", that is a finding with a systemic fix.

## Function-level authorization (BFLA)

- Admin/privileged routes must be gated by role check on the *server*, per route, not by hiding the button or by route naming.
- Grep: `app.use('/admin'`, `router.use(requireAdmin)`, `before_action :authenticate_admin`, decorators `@Roles`, `requireRole(`. Then check for routes registered *outside* that middleware chain — ordering bugs (`app.use(session)` after the protected router) are real and common.
- Method escalation: middleware applied to `GET` only; `OPTIONS`/`HEAD`/`PATCH` unprotected; `X-HTTP-Method-Override` honoured.
- Job/queue consumers and cron handlers frequently skip the authz the HTTP path enforces. Same sibling rule.

## Next.js / middleware specifically

- **CVE-2025-29927** (fixed 12.3.5, 13.5.9, 14.2.25, 15.2.3) let a request bearing `x-middleware-subrequest` skip middleware entirely — the lesson outlives the CVE: **middleware is not an authorization boundary**. Check the version floor *and* whether authz lives only in `middleware.ts`. Correct posture: authorize in the route handler / server action / data layer; middleware is a redirect convenience.
- `matcher` config: routes not matched by the matcher have no middleware protection at all. Enumerate matcher patterns and diff against the route tree.
- Server Actions (`'use server'`) compile to public POST endpoints. Any exported action is callable by anyone who can reach the app. Each action needs its own auth + authz + input validation — never inherited from the page that renders the form.
- `use client` components receive serialized props from the server; anything passed down is readable in the browser payload. Secrets, internal ids, and other users' data passed as props leak without a single XSS.

## Sessions

| Control | Check |
|---|---|
| Cookie flags | `HttpOnly`, `Secure`, `SameSite=Lax|Strict` (None requires `Secure` + CSRF token), `__Host-` prefix for the session cookie, scoped `Path`, no `Domain` wider than needed |
| Rotation | new session id on login *and* on privilege change; old id invalidated server-side |
| Fixation | does the app accept a client-provided session id? |
| Lifetime | absolute + idle expiry; "remember me" reviewed as a separate, longer-lived token |
| Revocation | logout/password change invalidates **all** sessions server-side; stateless JWT needs a denylist/generation counter or short TTL + refresh rotation |
| Storage | server-side store with httpOnly cookie is the baseline; `localStorage` tokens are readable by any XSS (a design finding, not a bug) |
| CSRF | token bound to session, `SameSite` as defence in depth, origin check on state-changing requests |
| Session in URL | sid in query/path → leaks via Referer, logs, shared links |

## JWT

Verify, don't decode. Each line is a separate finding if wrong:

- `algorithms: ['RS256']` **pinned**. Loading `jsonwebtoken.decode` result as identity (no verify) is critical.
- `alg: none` accepted (older/naive libs), algorithm confusion (RS256 pubkey accepted as HS256 secret) — pinning the algorithm list kills both.
- Secret strength and management: HS256 secret from env, ≥256 bits, not a default/committed value.
- `jku`/`x5u`/`jwk`/`kid` header trusted → key injection or path traversal in `kid` (`../../dev/null` with HS256 → forged tokens). Ignore all four; select keys from a fixed map.
- Claims actually enforced: `exp` (with small skew), `nbf`, `aud`, `iss`, and a `sub` that maps to a live user. A token with a valid signature but no `aud` check is replayable across services.
- Revocation path exists for logout/role change; long access-token TTLs (>15 min) with no rotation are a design finding.
- Storage: not in `localStorage`; refresh token in httpOnly cookie with rotation + reuse detection.

## OAuth / OIDC (as client, and as provider)

- **Client:** `state` present and verified (CSRF/login-CSRF), PKCE (`S256`) used for public clients, `redirect_uri` compared exactly (no prefix/regex match, no wildcard), authorization code single-use and bound to `code_verifier`, `nonce` checked for OIDC, id_token signature + `iss`/`aud`/`exp` verified (not just decoded), token endpoint response not trusted from the front channel.
- **Provider:** open redirect via `redirect_uri` registration, missing exact match, `response_type=token` in a public client, scope upgrade without consent, refresh token issued to public clients without rotation.
- "Login with X" account-linking: linking by email without email-verified proof → account takeover. Check `email_verified` is required before merging.
- SSO callbacks that create users: is email domain/tenant validated before auto-provisioning?

## Password and credential flows

- Reset token: 32+ random bytes, hashed at rest, single use, short TTL (<1 h), invalidated on use and on password change, delivered to the *verified* address, not returned in the response or logged.
- Reset endpoint does not reveal account existence (uniform response), and is rate-limited per account + per IP.
- Token in URL vs form → referrer/log leakage.
- Password hashing: argon2id/bcrypt/scrypt with sane params; MD5/SHA1/PBKDF2-low are findings. bcrypt 72-byte truncation caveat.
- Login enumeration via message or timing; brute force protection (per-account lockout/backoff, not per-IP only).
- MFA: verified server-side, bypassable by dropping the challenge step (does the session become authenticated before the second factor?), recovery codes single-use and hashed, TOTP replay window.
- Signup: role/tenant never taken from the request body (see mass assignment); first-user-is-admin bootstrap reviewed.

## Service-to-service and webhooks

- Shared secrets compared with `===` (timing) — use `crypto.timingSafeEqual`.
- Inbound webhooks: signature verified over the **raw** body (not re-serialized JSON), timestamp tolerance against replay, shared secret per tenant, delivery id deduped (idempotency).
- Outbound callbacks with tokens in query strings → logs.
- Internal APIs trusting headers (`X-User-Id`, `X-Forwarded-User`, `X-Original-URL`) that a client can set unless the ingress strips them. Check the ingress config, then say which one you verified.
- mTLS/api keys scoped to tenant and rotated; a "global" API key in a multi-tenant system is a design finding.

## Fast greps

```bash
rg -n "findUnique\(|findFirst\(|findById\(|objects\.get\(|get_object_or_404" --type ts --type py
rg -n "jwt\.(decode|verify)|algorithms:|jsonwebtoken|jose"
rg -n "localStorage\.(set|get)Item\(.*(token|jwt|session)"
rg -n "cookie\(|setHeader\('Set-Cookie'|SameSite"
rg -n "'use server'|middleware\.ts|matcher"
rg -n "X-User-Id|X-Forwarded-User|X-Original-URL|X-HTTP-Method-Override"
rg -n "state|redirect_uri|code_verifier|nonce" --glob "*auth*"
```

## False positives

- Public-by-design resources (published posts, public profiles) — IDOR needs a boundary.
- `findUnique({where:{id}})` followed by an explicit ownership check in the same handler is fine; verify the check is before the sink and on every branch.
- Sequential numeric ids are not a vulnerability by themselves; they are a *discovery* aid. Report only the missing control.
- A JWT in `localStorage` in a throwaway internal tool with SSO-only users: still worth one line, not a critical.

# Pack: Client / React / Next.js

Applies to React 18/19, Next.js (App Router and Pages), Vite SPAs, Vue 3 / Nuxt, and Svelte 5 / SvelteKit.
Read the React sections for the invariants, then the Vue/Svelte sections for that framework's sinks.

Browser-side findings are mostly about **two trust errors**: treating the browser as a security boundary, and trusting data that crossed from server to client (or back).

## The one rule that generates most findings

Anything the browser can see, the user can see; anything the browser sends, the user can forge. So:

- Authorization on the client is UX. The server must re-check every action.
- Anything in a bundle, a prop, a serialized payload, or a `NEXT_PUBLIC_` variable is public.
- Anything sent to the server is attacker-controlled, including hidden fields, ids, prices, and "disabled" inputs.

## XSS sinks in React

React escapes text children by default — `{userInput}` is safe. Findings live at the escape hatches:

| Sink | Why it matters |
|---|---|
| `dangerouslySetInnerHTML` | only safe with DOMPurify (or equivalent) applied at render, with a config that keeps `href`/`src` protocols; grep every use and check the sanitizer is actually applied to *this* value |
| `href={userInput}` / `src={...}` / `formAction` | `javascript:` and `data:text/html` URLs execute; validate protocol via `new URL()` against `http|https|mailto` |
| markdown renderers | `react-markdown` is safe by default; `rehype-raw`, `allowDangerousHtml`, `marked` + `dangerouslySetInnerHTML`, `dompurify` missing → XSS |
| syntax highlighters | older `highlight.js` `innerHTML` paths with `class=` names; check version |
| `element.innerHTML =` in an effect or a ref | same as above, easy to miss in a hook or a chart tooltip |
| `document.write`, `eval`, `new Function`, `setTimeout(string)` | direct sinks |
| SVG upload/render | SVG is script-capable; inline `<svg>` from user content, or `<img src>` pointing to a user SVG on the same origin |
| third-party widgets loaded with `innerHTML` into an admin page | self-XSS chains with an open redirect become real |

Also: **DOM clobbering** on `name`/`id` collisions with globals, and **mutation XSS** in libraries that take HTML strings (`toast`, `tooltip`, `modal`, `pdf` renderers). Check every package that accepts `html`/`content`/`label` props fed from user data.

## XSS sinks on the server, rendered for the browser

- Next.js `next.config` `dangerouslyAllowSVG: true` on an image optimizer → SVG script execution; requires `contentSecurityPolicy` in the same config.
- User content reflected into a `not-found` page, error page, OG image, or sitemap without escaping.
- `Content-Type: text/html` when serving user-uploaded files.

## CSP, if present, check it does something

- `unsafe-inline` in `script-src` without a nonce/hash → no XSS mitigation.
- `default-src *` or `script-src 'self' 'unsafe-eval'` in prod.
- Missing `frame-ancestors` (clickjacking on authenticated UI), missing `object-src 'none'`, `report-uri` without a collector.
- Next.js: a nonce-based CSP requires middleware + `nonce` on every `<Script>`; a hardcoded CSP in `next.config` headers can be duplicated and silently overridden. Report the effective policy, and say how you determined it.

## Server → client data flow (Next.js)

- **RSC payloads.** Props passed from a Server Component to a Client Component are serialized into the page and readable in the browser. Internal ids, feature flags, other users' emails, DB rows passed "just in case" are leaks. Grep `<Client` usage with large objects.
- **Server Actions** (`'use server'`) are public POST endpoints with stable ids. Each one needs: authentication, authorization on the *object*, schema validation, and a returned value that does not over-share. An action that trusts a `userId`/`role` argument from the client is a critical.
- **`NEXT_PUBLIC_`** variables are inlined into the bundle. Grep `.env*` for `NEXT_PUBLIC_.*(KEY|SECRET|TOKEN|PASSWORD|PRIVATE)`. Also: any variable referenced in client code, even without the prefix, ends up visible if the bundler inlines it.
- **Route handlers** under `app/**/route.ts` are server code — verify authz per handler, not per layout. Layouts do not protect their children.
- **Middleware**: see `auth-and-sessions.md` — authorization belongs in the handler/data layer (CVE-2025-29927's lesson), not only in `middleware.ts`.
- **Caching**: `fetch` with `cache: 'force-cache'` or `unstable_cache` shared across users, `revalidate` on a personalized route, and Next's full route cache serving one user's HTML to another. Check that personalized data use `no-store` or are scoped by cookie/`Authorization`.
- **Image/upload proxies** (`/api/proxy?url=`) → SSRF with the server's identity.

## Token and session storage in the browser

- Access tokens in `localStorage`/`sessionStorage`/non-httpOnly cookies are XSS-reachable. Correct: httpOnly session cookie, or in-memory access token + httpOnly rotating refresh cookie.
- Tokens in URLs, in `window.name`, in `postMessage` to `*`, or in analytics events.
- "Remember me" storing credentials or long-lived tokens unencrypted.
- Logout that only clears client state — the token stays valid server-side.

## postMessage / iframes / embedded widgets

- `addEventListener('message', h)` without `event.origin` allowlist check → any framed or framing page can drive the handler.
- `postMessage(msg, '*')` sending tokens, PII, or auth state to any origin.
- `targetOrigin` derived from `document.referrer` or a query param.
- Inbound handlers that act on unvalidated payloads (`{type:'navigate', url}`) → open redirect / javascript: navigation.
- `window.opener` not nulled for OAuth popups (`rel="noopener"`); iframe `sandbox` missing on user content.

## Client-side storage and caching leaks

- PII or tokens in `IndexedDB`/`localStorage` beyond session need; no clear on logout.
- Service worker caching authenticated API responses (shared device, back-button after logout).
- Redux/Zustand persisted to storage with tokens; React Query persisting user data across account switches (cache not cleared on logout).
- Next.js prefetch of authenticated routes caching responses in the router cache; `<Link prefetch>` on admin routes.

## Prototype pollution (client + shared libs)

- Grep `Object.assign({}, JSON.parse(...))` with deep merge, `lodash.merge`/`set`/`zipObjectDeep` on request data, `deepmerge`, `qs` with `allowPrototypes`, custom `setPath` loops.
- Payload shape: `{"__proto__":{"isAdmin":true}}`, `constructor.prototype`.
- Check the runtime floor: `qs` ≥ 6.10.3, `lodash` ≥ 4.17.21, `minimist` ≥ 1.2.6, `serialize-javascript` ≥ 3.1.
- Client-side effect: pollution of checks like `if (user.isAdmin)`. Server-side effect when the same body is parsed by Node.

## Routing, redirects, and framing

- Open redirect: `?next=`/`?returnTo=`/`?redirect=` used in `router.push()` or `location.href` without an allowlist (same-origin path only, reject `//evil.com`, `\/\/`, `%2F%2F`, `javascript:`).
- Path-based auth in the client (`if (pathname.startsWith('/admin'))`) with no server check.
- Referrer leakage of tokens/ids in URLs (`Referrer-Policy` missing, `rel="noreferrer"` absent on external links).

## Third-party scripts

- Analytics/session-replay (`Hotjar`, `FullStory`, `PostHog`, `Sentry`) capturing DOM text and inputs — check masking config for forms and PII. Session replay on a page with a card form is a real finding.
- `Sentry.init({ sendDefaultPii: true })`, `beforeSend` not scrubbing headers/cookies.
- Scripts loaded without SRI from a CDN; `integrity` absent on third-party `<script>`.
- Tag managers on authenticated pages (any tag can read the DOM).


## Vue 3 / Nuxt

Same invariants as React, different sinks and one different framing model.

- `v-html="x"` is `dangerouslySetInnerHTML`: only safe after DOMPurify, applied at render to *that* value. `v-bind:href`/`:src` with a user value allows `javascript:` — validate the protocol.
- Render functions and `<component :is>` fed user data; `innerHTML`/`insertAdjacentHTML` in directives or composables.
- Nuxt: `runtimeConfig.public` is serialized into the client payload — treat it exactly like `NEXT_PUBLIC_`. Secrets belong in `runtimeConfig` (private) only.
- Nuxt `server/api/*.ts` handlers are the API: each needs its own authn + authz + validation. Route middleware in `middleware/` is client-side unless it's `server/middleware/`, and it is still not an authz boundary — authorize in the handler or the data layer.
- Nuxt `useAsyncData`/`useFetch` results are hydrated into the page payload: whatever the server fetched is readable in the browser.
- `navigateTo()` / `useRouter().push()` with a query-derived target → open redirect (`//evil.tld`, `javascript:`).
- `routeRules` with `swr`/`isr` caching on authenticated pages → cross-user response reuse.

## Svelte / SvelteKit

- `{@html ...}` is the XSS sink; sanitize with DOMPurify or don't render HTML. `{@html}` from markdown is the common case.
- Svelte escapes normal `{expr}` interpolation — do not report it.
- `+page.server.ts` / `+layout.server.ts` `load` returns are serialized into the page: same leak as RSC props. Anything returned is public — no secrets, no other users' rows, no internal flags.
- `+page.server.ts` **form actions** (`export const actions = {...}`) compile to public POST endpoints. Each one needs authentication, object-level authorization, and schema validation — never inherit it from the page that renders the form.
- `hooks.server.ts` `handle()` is the middleware equivalent: it populates `event.locals`, it does not authorize per route. Check that handlers read `locals.user` and enforce ownership; a populated `locals` with an unchecked route is the SvelteKit version of CVE-2025-29927's lesson.
- CSRF: SvelteKit's `csrf.checkOrigin` (on by default) covers form actions. Disabling it, or accepting `application/json` state-changing requests without an origin check, is a finding.
- `+server.ts` endpoints (`GET`/`POST` exports) are public — same per-handler rule.
- `PUBLIC_`-prefixed Vite env vars are inlined into the client bundle; anything without the prefix that is referenced in client code still ships if the bundler inlines it.
- `ssr = false` / prerendered pages change *where* data is fetched, not who may fetch it — a client-side fetch to an unprotected endpoint is still unprotected.
- `adapter-*` and `vite.config` `define` entries that inject secrets at build time.

## Starter greps

```bash
rg -n "dangerouslySetInnerHTML|innerHTML\s*=|outerHTML|document\.write"
rg -n "href=\{[^}]*(url|link|redirect|next)|location\.href\s*=|router\.(push|replace)\([^)]*(next|redirect|url)"
rg -n "NEXT_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|PRIVATE)"
rg -n "postMessage\(|addEventListener\(['\"]message"
rg -n "localStorage\.(setItem|getItem)\(.*(token|auth|jwt|user)"
rg -n "'use server'" -A 12
rg -n "cache:\s*'force-cache'|unstable_cache|export const revalidate"
rg -n "dangerouslyAllowSVG|Content-Security-Policy|unsafe-inline|unsafe-eval"
rg -n "deepmerge|lodash\.(merge|set)|__proto__|allowPrototypes"
```

## False positives

- `dangerouslySetInnerHTML` with a constant string or a value that came from a trusted CMS with sanitization *and* you verified the sanitizer config.
- `{user.name}` in JSX — React escapes it. Do not report React text interpolation.
- A token in `localStorage` when the app has a strict nonce CSP, no user-generated HTML, and no third-party scripts — still a hardening line, not a critical. Say which precondition makes it matter.
- `postMessage` without an origin check in a page that cannot be framed and never opens popups — reachability decides.
- `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, and other publishable keys: intended to be public. Check that the *policy* behind them restricts what a client can do (RLS on, bucket policy, restricted key).

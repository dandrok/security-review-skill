# Pack: Node server frameworks (Express, Fastify, Hono, Nest)

Applies to HTTP backends in Node/TypeScript when the framework is Express, Fastify, Hono, or NestJS. The generic sinks are in `api-and-injection.md`; this pack is about **where each framework makes authorization leak** — usually through ordering, scoping, or a validation layer that isn't switched on.

Read the framework section for the stack you have. If a repo has two (Nest + Express adapter is normal), read both.

## Cross-framework first principles

1. **Registration order is a security control.** A route added after the auth middleware today can be added before it tomorrow. Prefer routers with the check attached, not a global stack someone must remember to append to.
2. **A plugin/module boundary is not an authz boundary.** Encapsulated hooks, nested routers, and lazy-loaded modules routinely protect one sibling and not the other. Check per route, not per mount.
3. **Validation off by default is the norm.** Express has none, Fastify needs a schema per route, Hono needs an explicit validator, Nest needs a global pipe. Absence is silent, which is why every DTO/handler needs its own check.
4. **Serialization leaks more often than deserialization.** Returning an ORM entity ships password hashes, internal ids, tenant ids, and soft-delete flags.

## Express

**Order and mounting**

- `app.use(auth)` before or after route registration — anything registered earlier is unprotected. Grep the entry file and read it top to bottom once; this is a 2-minute check that finds real bugs.
- `app.use('/admin', requireAdmin, adminRouter)` protects the mount. `adminRouter.get('/users', ...)` inside it inherits it. A second `app.get('/admin/export', ...)` in the main file does **not**.
- Error handlers must be 4-arity and last; a `try/catch` that swallows leaves the request hanging instead of failing closed.
- Express 4: an `async` handler that throws never reaches the error handler (unhandled rejection). Either every handler is wrapped, or you're on Express 5 (which forwards rejections). Check `package.json` — this affects whether failures fail open.
- `router.use(...)` applies to that router's paths only; `app.use(...)` after mounting applies to everything from that point.

**Trust and identity**

- `app.set('trust proxy', true)` + rate limiting or IP allowlists on `req.ip` = bypass: the client supplies `X-Forwarded-For` and picks its own identity unless the edge strips it. Correct: `trust proxy` = the exact hop count, or a function with known proxy IPs.
- Host header poisoning: password-reset links built from `req.hostname`/`req.headers.host` → attacker sets `Host: evil.tld`, victim receives a valid-looking reset link pointing at the attacker. Grep for `req.hostname`, `req.headers.host`, `X-Forwarded-Host`.
- `req.query` is attacker-shaped: `?role[ne]=x` becomes an object. Anything passing `req.query` straight to Mongo/`find` is injection (see `api-and-injection.md`).

**Body and transport**

- `express.json()` default limit is 100 kb — verify a limit exists at all, plus `express.urlencoded({extended: true})` (qs parsing) and multipart limits (`multer({limits:{fileSize}})`, filename handling).
- Session middleware: `secret` from env, `cookie: {httpOnly, secure, sameSite}`, and a real store (`connect-redis`, `connect-pg-simple`) — the default `MemoryStore` leaks memory and loses sessions on restart.
- Static: `express.static(root, {dotfiles:'deny', index:false, fallthrough:false})`; confirm the root doesn't contain `.env`, `.git`, source maps, or uploads served with `Content-Type: text/html`.
- CORS: `cors({origin: true, credentials: true})` reflects any origin; regex `/example\.com/` matches `example.com.evil.tld`.
- `helmet()` absent, or `contentSecurityPolicy:false` while the app renders HTML.
- Password reset / email templates with `res.send(userInput)` → reflected XSS on the API origin.

**Mass assignment and leaks**

- `Object.assign(user, req.body)`, `new User(req.body)`, `await Model.update(req.body)` — explicit field picks only.
- `res.json(user)` returning the ORM entity including `passwordHash`, `resetToken`, `internalNotes`.
- Query-string driven sort/filter passed to the ORM (see `sql-and-data.md`).

## Fastify

- **Schema per route is the validation.** No `schema:` on the route = unvalidated body/query/params. Grep `fastify.get|post|route(` and count routes with vs without `schema`. Response schemas also *strip* unknown properties — their absence is how a password hash escapes.
- **Plugin encapsulation:** `fastify.register(plugin)` creates a scope; a hook added inside plugin A does not apply to plugin B. An auth hook registered inside the admin plugin protects only that subtree — usually intended, sometimes assumed to be global. Check where `addHook('onRequest'|'preHandler', auth)` sits relative to route registration.
- Hook order: `onRequest` (no body yet) → `preParsing` → `preValidation` → `preHandler` (body parsed, validated) → handler. Authz that needs body fields must run in `preHandler`, not `onRequest`.
- `bodyLimit` on the instance and per route; `@fastify/multipart` with `limits` and `fileSize`; `@fastify/rate-limit` on auth endpoints specifically.
- `@fastify/cors` with `origin: true` or `['*']` + `credentials: true`; `@fastify/helmet` absent; `@fastify/cookie` without `httpOnly/secure/signed`.
- Error handling: the default serializer in production hides stack traces, but a custom `setErrorHandler` that `reply.send(err)` reopens the leak. Same for `logger: true` writing bodies to stdout.
- `decorateRequest('user', null)` then mutating per-request is fine; sharing a mutable object across requests is not.
- Positive signals worth noting in the report: schemas present, `additionalProperties: false`, response serializers defined.

## Hono

- Middleware runs in registration order per path pattern: `app.use('/api/*', auth)` must be registered before `app.route('/api', apiRouter)`; a route added earlier is unprotected.
- Validators are opt-in: `@hono/zod-validator` (or `hono/validator`) per route. `await c.req.json()` without a validator is unvalidated input.
- `c.get('user')`/`c.set('user', ...)` — a handler reading `user` on a route with no auth middleware gets `undefined`; if the code does `if (user.role === 'admin')` that's a silent bypass, if it does `user.id` it's a 500. Trace both.
- Edge/runtime split: on Workers there's no `process.env`; secrets come from bindings — check no binding is forwarded to the client bundle and that local dev emulation doesn't differ from prod.
- `cors()` defaults to `origin: '*'` without credentials — with `credentials: true` and a reflected origin, it's permissive CORS. `secureHeaders()` absent means no CSP/HSTS.
- `c.req.raw` passed into other runtimes (fetch handlers, sub-apps) skips Hono's middleware chain entirely.
- `app.notFound`/`onError` handlers that echo request data.

## NestJS

Bugs cluster in four places: guard coverage, DTO validation, serialization, and resolver/action gaps.

**Guard coverage**

- Global auth is normally `{ provide: APP_GUARD, useClass: JwtAuthGuard }`. Then `@Public()` must be *honoured* by that guard — check the guard reads `IS_PUBLIC_KEY` via `Reflector.getAllAndOverride([IS_PUBLIC_KEY, ...], [handler, class])`. A guard that checks only the class metadata silently protects nothing when a method overrides it.
- `@UseGuards(RolesGuard)` on a controller does not cover routes added in a different controller. Enumerate `@Controller(` blocks, then check each has a guard (global, class, or method).
- Guard order is registration order; a `RolesGuard` before `JwtAuthGuard` sees no user and (if written as `user?.role !== x`) may throw or pass. Read the failure branch: `return false` is fail-closed, `if (!user) return true` is not.
- Guards run *before* pipes and before the handler, with the body already parsed by the Express/Fastify adapter. Authorizing on body fields inside a guard is therefore possible — and easy to forget when the route moves.
- GraphQL resolvers (`@Resolver`, `@Query`, `@Mutation`) bypass controller-level guards; they need their own `@UseGuards`. Same for `@MessagePattern`/`@EventPattern` microservice handlers and `@Cron` jobs.
- `@nestjs/graphql` + `@nestjs/passport` combination: check the *resolver* has the guard, not just the module providing it.

**ValidationPipe (the overposting gate)**

- `new ValidationPipe({whitelist: true, forbidNonWhitelisted: true, transform: true})` global, or per-route. Without `whitelist`, unknown fields survive into the entity: `POST /users {"email":"x","role":"admin"}` only fails if the DTO has `forbidNonWhitelisted` **and** the handler doesn't spread the raw body.
- `transform: true` is what converts `?limit=10` to a number. Without it, query DTOs receive strings, class-validator numeric decorators don't run as expected, and `skip`/`take` accept `1e9`.
- `enableImplicitConversion: true` coerces types beyond the DTO's intent; check what it does to booleans (`"false"` → `true` in some setups).
- `@Body() body: any` or `@Body() dto: SomeInterface` (interface, not class) — no validation runs at all, because Nest validates by class metatype.

**Serialization and leaks**

- Returning the TypeORM/Prisma entity from a controller ships every column. Fix: `@Exclude()` + `ClassSerializerInterceptor` globally, or an explicit response DTO. Grep for `return this.repo.find*(` directly in controllers.
- `@Expose()` allowlists are safer than `@Exclude()` denylists — a new column is exposed by default with denylists.
- Query DTOs echoed back in error messages; `ValidationPipe` with `disableErrorMessages: false` in prod replies with full constraints (usually fine, sometimes discloses internals).

**Auth implementation**

- Passport `JwtStrategy.validate()`: does it load the user and check status/revocation, or return the decoded payload? Returning the payload means a deleted user, revoked role, or disabled account keeps working until the token expires.
- `ignoreExpiration: true` anywhere is a finding.
- `secretOrKey` from env, `algorithms: ['RS256']` pinned (see `auth-and-sessions.md`).
- Session/JWT + `@nestjs/throttler`: default `ttl`/`limit` are often absurdly permissive; check the login route has a stricter override.
- `FileInterceptor` / `FilesInterceptor` without `limits` (size, count) and with `diskStorage` derived from the client filename.

**Multi-tenancy**

- Request-scoped providers (`Scope.REQUEST`) or `AsyncLocalStorage` carry the tenant. A `@Injectable()` singleton that stores tenant state on `this` leaks across concurrent requests — this is the Nest-specific version of a shared-state bug and it is common.
- `findOne({where:{id}})` in a service that assumed the repository layer adds `tenantId` — verify the repository, not the call site.

## Greps

```bash
# Express
rg -n "app\.use\(|router\.use\(|express\.static|trust proxy|req\.headers\.host|req\.hostname" --type ts
rg -n "express\.json\(|urlencoded\(|cors\(|helmet\(|session\(" --type ts
rg -n "Object\.assign\([^,]+,\s*req\.body|new \w+\(req\.body\)" --type ts
# Fastify
rg -n "addHook\(|register\(|schema:|bodyLimit|setErrorHandler" --type ts
# Hono
rg -n "app\.use\(|zValidator|validator\(|c\.set\(|c\.get\(|secureHeaders" --type ts
# Nest
rg -n "@Controller\(|@UseGuards\(|APP_GUARD|IS_PUBLIC_KEY|@Public\(\)|Reflector" --type ts
rg -n "ValidationPipe\(|whitelist|forbidNonWhitelisted|transform:" --type ts
rg -n "@Body\(\)\s*\w+:\s*(any|I[A-Z])|return this\.\w+\.(find|findOne|findAll)" --type ts
rg -n "ignoreExpiration|secretOrKey|algorithms:" --type ts
rg -n "Scope\.REQUEST|AsyncLocalStorage|this\.tenant" --type ts
```

## False positives

- A route registered before the auth middleware in a file that is mounted *after* `app.use(auth)` — registration order within a router matters, but the parent's mount point decides when it runs. Read the entry file, don't guess from the router file.
- `@Public()` on a genuinely public endpoint (health, login, webhooks with signature verification) — check the webhook verifies its signature before accepting.
- A Fastify route without `schema` where the handler validates with zod manually — the validation exists, just not declaratively.
- `trust proxy` set correctly with an edge that strips client-supplied `X-Forwarded-*` — verify the edge config or mark `needs_validation`.
- Nest `@Body() dto: CreateUserDto` returning the full entity from a *service* that the controller then maps — read the controller's return, not the service's.

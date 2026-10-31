# Changelog

## 1.2.0 — 2026-10-31

Routing accuracy for frontend stacks that are not React, plus dependency-aware detection.

- **`client-react.md` -> `client-web.md`** and new sections for **Vue 3 / Nuxt**
  (`v-html`, `runtimeConfig.public`, `server/api` handlers, `useAsyncData` hydration,
  `navigateTo` open redirect, `routeRules` caching) and **Svelte 5 / SvelteKit**
  (`{@html}`, `+page.server.ts` load leaks, form actions as public endpoints,
  `hooks.server.ts` is not authz, `csrf.checkOrigin`, `PUBLIC_` env, `+server.ts`).
- **`classify-stack.py` reads manifests**, not just filenames: `package.json`
  dependencies, `requirements.txt`, `pyproject.toml`. A Svelte, Nest or Drizzle repo
  that looks like plain TypeScript now routes correctly.
- New file signals: `*.vue`, `*.svelte`, `svelte.config.*`, `nuxt.config.*`,
  `+page.server.ts`, `+server.ts`, `+layout.server.ts`.

## 1.1.0 — 2026-10-31

Backend and data-layer coverage, so the skill stops going shallow outside Next.js.

- **New pack `server-node.md`** — Express (middleware order, `trust proxy`, Host-header
  poisoning, session store, async failures), Fastify (per-route schemas, plugin
  encapsulation, hook order), Hono (validator opt-in, `c.get` on unprotected routes,
  edge bindings), Nest (guard coverage, `@Public()`, `ValidationPipe` whitelist and
  overposting, serialization leaks, Passport `validate`, request-scoped tenancy).
- **New pack `sql-and-data.md`** — Postgres grants, RLS (`FORCE`, `WITH CHECK`,
  `security_invoker` views, `SET LOCAL` tenant identity), `SECURITY DEFINER` and
  `search_path`, server-side file/RCE paths, Supabase `service_role`/`anon`; SQLite's
  no-authz model (file permissions, `ATTACH`, `trusted_schema`, libSQL tokens); MySQL
  `FILE` / `sql_mode` / `DEFINER` notes; ORM escape hatches per stack; migrations,
  backups, connection and pooling pitfalls.
- **Scope made explicit** in `SKILL.md`: a "Covers / doesn't cover" table, so a Python
  or Go review is not mistaken for full coverage.
- **Routing**: two new rows plus new `classify-stack.py` signals (`nest-cli.json`,
  `*.module.ts`, `*.guard.ts`, `*.controller.ts`, `schema.prisma`, `drizzle.config.*`,
  `knexfile.*`, `*.sql`, `migrations/`, `supabase/`, `*.db`/`*.sqlite`).
- **Tests**: fixture now carries Nest + Prisma + SQL signals; 10 assertions.

## 1.0.0 — 2026-10-31

First release: 7 packs (API/injection, auth/sessions, client React, secrets/config,
supply chain, cloud/deploy, AI/LLM), reporting rubric and findings schema, three
scripts (stack classifier, scanner runner, findings validator), 8 offline semgrep
rules, and a vulnerable-fixture test suite.

# Changelog

## 1.3.1 — 2026-11-13

The gates, made to fail where they were passing. Found by running the suite on a machine
that does not have the three scanners.

- **`scan.sh` no longer reports a clean scan it did not run.** It tracks each scanner as
  ran / errored / not installed / deliberately skipped and prints a `coverage n/3` line on
  every run. `--strict` now exits **3** when coverage is incomplete (it kept exit **1** for
  real findings), and a `--skip` counts as a deliberate omission while a missing binary does
  not. A missing `rules/` directory is a failure, not a silent skip. `scan-summary.json`
  carries the same `coverage` object, so a caller can assert instead of read.
- **Stale reports are cleared before scanning**, so a previous run's `gitleaks.json` cannot
  be read as this run's evidence.
- **`classify-stack.py` routing:** `**/*rag*` sent any file named `Average.js` to the AI pack
  (it hit three repos on the author's machine). RAG is now a directory or a module; `agents/`
  must contain code, because `.claude/agents/*.md` is config and not an LLM surface; the
  over-broad `tools/` signal is gone; agent-config dirs (`.claude`, `.cursor`, `.codex`,
  `.gemini`) are skipped. `**/mcp*.{json,ts,py}` never matched anything — `fnmatch` has no
  brace expansion — and is now one pattern per extension.
- **`validate-findings.py --root <tree>`** closes the hallucinated-citation hole: every
  evidence file must exist in the reviewed tree and the line must be inside the file, a
  `confirmed` `control_gap` must cite a line, a coverage row may not name a finding that does
  not exist, and a path that escapes the root is rejected. Without `--root` the check stays
  schema-only, so nothing breaks for callers that do not have the tree.
- **`SKILL.md`:** audit mode's "3–5 packs" contradicted the four-pack cap in Step 1 and in the
  done criteria; audit is now 3–4 and the cap says it does not grow with the mode. New step:
  run `scan.sh` first and read its coverage line, with the exit-code table.
- **`tests/run.sh`:** 30 assertions and 3 skips instead of 13 assertions that failed on any
  machine without all three scanners — a missing scanner now reports SKIP and the run still
  exits 0. New checks force the paths nobody runs by hand: no scanners on `PATH`, a crashing
  scanner, a `--root` citation that does not resolve, an evidence line past EOF, a
  `control_gap` with no line, and a coverage row naming an unknown finding. Each was verified
  to go red with its fix reverted.
- README token counts re-measured with `o200k_base` (`SKILL.md` 3,765; all 11 docs ~24,900;
  scripts 8,618).
- **README rewritten, then cut to size.** It answers three questions — why the skill exists, how to
  install it, what it covers — with the agent-install prompt first (paste the repo URL, the agent
  copies the folder and confirms), then `gh skill install` for the 48 harness layouts it knows, then
  `install.sh` for offline/Hermes. Reference material moved out: per-harness paths and the four
  gotchas to `docs/install.md`, the pack index to `docs/packs.md`. 139 lines, against 187 before and
  Cloudflare's 106. Dropped `npx skills`: an unpinned `npx` of a third-party package is the
  install-time risk this skill's own supply-chain pack tells you to flag.

## 1.3.0 — 2026-11-03

Rust coverage, written from a real review that found a real bug the pack would have
caught sooner.

- New pack `references/rust-cli.md`: panics as denial of service, allocation ceilings
  from untrusted lengths (the `with_capacity(header.size())` class), paths, symlinks
  and TOCTOU, `Command` vs `sh -c`, serde depth and allow-by-default fields, terminal
  escape injection, unauthenticated loopback servers, TLS verification, `build.rs`
  and proc macros, `cargo audit` / `cargo deny`.
- The pack leads with what is **not** a finding in Rust — memory-safety classes and
  `unsafe` on its own — because that is where a Rust review wastes its report.
- Coverage table now names Rust instead of lumping it into "not covered".
- `classify-stack.py` reads `Cargo.toml`: `*.rs`, `Cargo.toml` and `build.rs` route to
  the Rust pack, and crate names route too (axum/actix-web/rocket/warp to
  api-and-injection, sqlx/diesel/rusqlite to sql-and-data).
- `tests/run.sh` asserts both the file routing and the crate routing.

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

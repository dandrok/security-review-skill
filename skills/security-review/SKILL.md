---
name: security-review
description: "Security review of a web codebase, diff, or PR: find vulnerabilities that violate a real trust boundary, with source evidence, severity, and the smallest effective fix. Primarily TS/JS web apps — React/Next, Express/Fastify/Hono/Nest, Postgres/SQLite/MySQL — other stacks at sink level. Use for security questions, threat models, pre-merge review, secret/dependency audits, AI/LLM and MCP code. Write audit artifacts only when explicitly asked."
license: MIT
compatibility: [claude-code, antigravity, antigravity-cli, opencode, codex, gemini-cli, cursor, hermes]
metadata:
  version: 1.2.0
  author: dandrok
  source: https://github.com/dandrok/security-review-skill
  frameworks: [OWASP-ASVS-5.0, OWASP-LLM-Top10-2025, OWASP-Agentic-Top10-2026, CWE]
---

# Security Review

Find vulnerabilities that violate a **real trust boundary**, prove each one from source, and hand back the smallest fix that closes it. This is a defensive, source-first, read-only workflow.

The hard part of AI security review is not finding suspicious code — it is not reporting 40 plausible non-issues. Everything below is built around that failure mode: a candidate only becomes a finding when you can name who attacks, what they reach, and which control should have stopped it.

## Covers / doesn't cover

| | |
|---|---|
| **Strong** | TS/JS web apps: React/Next, Vue/Nuxt, Svelte/SvelteKit clients, Express / Fastify / Hono / Nest backends, Postgres / SQLite / MySQL data layers, plus auth, secrets, supply chain, cloud and deploy config, AI/LLM and MCP code |
| **Generic only** | Python (Django/DRF, FastAPI, Flask), Go, PHP, Ruby, Java — the injection sink list and the auth / secrets / supply-chain packs apply; framework-specific authorization semantics do not |
| **Not covered** | native and binary code, mobile, embedded, .NET, kernel, and anything that needs exploitation beyond a local proof |


## Modes

Loading this skill authorizes nothing else. Pick the mode from the request; if it is genuinely ambiguous, ask one question and default to **quick**.

| Mode | Trigger | Packs read | Writes |
|---|---|---|---|
| **quick** | "is this safe?", a diff, one file, a specific worry | 1–2 | nothing; answer in chat |
| **review** | "security review this PR/branch/service" | 2–4 | `.security-review/findings.md` if asked |
| **audit** | "audit", "full/comprehensive/end-to-end", "pen-test", "report" | 3–5 | `findings.json` + `REPORT.md` + coverage ledger |

Never run audit phases because the skill loaded. Never create a directory in quick mode.

## Non-negotiables

- **Source is read-only.** Never edit target code, never run `npm install`/`pip install`/builds/tests on an untrusted tree outside an OS sandbox (no network, scratch `HOME`, read-only target, CPU/time limits). If you cannot sandbox, reason from source and say so.
- **No live targets.** Do not contact deployed endpoints, third-party APIs, registries, identity providers, or other tenants — not even "safe" GETs. The only permitted probe is a local reproduction against dummy data.
- **Proof, not weaponization.** Stop at the smallest observable effect: a dummy record read, a wrong return value, a reflected string. No shells, no persistence, no lateral movement.
- **Secrets are radioactively handled.** Reference `file:line` and the secret *type*; never paste a live value into a report, chat, commit, or test fixture. Redact to first 4 chars + length.
- **Report only what the code proves.** Uncertainty is a `needs_validation` record with the exact missing fact, never a padded severity.

## Step 1 — Fingerprint, then load only what applies

Do this before reading any pack. Every pack costs tokens; unloaded packs cost nothing.

```bash
python3 scripts/classify-stack.py .        # prints detected stacks + suggested packs
```

If the script cannot run, use the signals column below. Then read **at most four** packs, and only for layers the code actually has.

| Signal in repo | Pack to read |
|---|---|
| `express`/`fastify`/`hono`/`@nestjs/*` in deps, `@Controller(`, `*.module.ts`, `*.guard.ts`, `server.ts` | `references/server-node.md` |
| `schema.prisma`, `drizzle.config.*`, `knexfile.*`, `*.sql`, `migrations/`, `supabase/`, `*.db`/`*.sqlite`, raw query calls | `references/sql-and-data.md` |
| react/next/vue/nuxt/svelte deps, `*.tsx`/`*.vue`/`*.svelte`, `app/`, `pages/`, `+page.server.ts` | `references/client-web.md` |
| HTTP handlers, routes, controllers, GraphQL/RPC schema, `express`/`fastify`/`hono`/Django/DRF/Laravel/Go net/http | `references/api-and-injection.md` |
| Login, session, JWT, OAuth, cookies, RBAC/roles, multi-tenant columns, `middleware.ts` | `references/auth-and-sessions.md` |
| `.env*`, config files, Dockerfile, CI YAML, logger/telemetry setup | `references/secrets-and-config.md` |
| `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`/`uv.lock`, `postinstall`, GH Actions, publish flow | `references/supply-chain.md` |
| Terraform/CDK/Pulumi, S3/GCS, k8s manifests, Vercel/Netlify/Fly config, reverse proxy | `references/cloud-and-deploy.md` |
| LLM calls, prompts, embeddings/RAG, tool calling, MCP servers, agent loops | `references/ai-and-llm.md` |

Also read `references/reporting.md` once, when you are about to write findings in review or audit mode.

State the selection out loud in one line: `Packs: client-web, auth-and-sessions (skipped: cloud, ai — no infra or LLM code)`.

## Step 2 — Map trust boundaries before hunting

Write 5–9 lines, no more. Skip this and you will hunt by vibes.

```
Principals:    anonymous → authenticated user → tenant admin → service → operator
Entry points:  each route/handler/job/webhook/queue consumer + auth requirement
Assets:        what is worth stealing/destroying (tenant data, tokens, money, code exec)
Controls:      where authz is decided, where input is validated, where output is encoded
Data:          stores touched, and which one is the tenancy boundary
Third parties: outbound calls, webhooks in, vendored code
```

Two properties to check on this map, because they generate most real findings:

1. **A control that exists in one path and not its sibling.** Bulk endpoint without the check the single-item one has; GraphQL resolver without the REST guard; admin route protected in middleware but the server action next to it is not.
2. **A gap between what one component guarantees and what the next assumes.** Client validates, server trusts. Gateway authenticates, app authorizes by header. ORM scopes by tenant, raw query does not.

## Step 3 — Hunt: invariant first

For every candidate, walk this loop. Stop when the invariant is settled either way.

1. **Principal** — the lowest-trust actor who can reach this input. "Authenticated user of another tenant" counts; "attacker" alone does not.
2. **Input** — the exact accepted value, path segment, header, field, or state transition.
3. **Control** — the check that should reject, bind, scope, or rate-limit it. Name the function and line, or record that no control exists.
4. **Path** — trace that value after the decision through parsing, normalization, storage, and re-use until the sink.
5. **Effect** — the smallest observable consequence, on dummy data.
6. **Fix** — the source-level change plus the regression test that would have caught it.

Depth bound: follow only paths that reach your assigned boundary or whose guarantees that boundary relies on. Do not wander the repo.

Check these forces on every path — they are where reviews earn their keep:

| Force | What breaks |
|---|---|
| Encoding | value validated as one encoding, consumed as another (URL, HTML, SQL, shell, regex, path) |
| Identity | ID from client used as the subject instead of the session |
| Scope | query filtered by tenant in one place, not in the join/aggregate/export |
| Time | token checked at issue, not at use; revocation, replay, race, TOCTOU |
| Defaults | reject-by-default vs allow-by-default lists, empty means "all" |
| Errors | failure path skips the check, or leaks internals |
| Concurrency | two requests pass the check, both commit |

## Step 4 — Validate by trying to disprove

Every candidate gets a fresh pass whose goal is to kill it. Do this yourself as a separate step, or delegate to a subagent with only the candidate, the cited lines, and no memory of how it was found — independence is the point.

Answer all four or the candidate is not confirmed:

1. **Reachability** — is the entry point actually routed, mounted, and exposed (not dead code, not behind a disabled flag)?
2. **Control absence** — is there truly no equivalent check elsewhere (guard, ORM scope, DB policy/RLS, reverse-proxy rule, framework default)?
3. **Exploitability** — can the named principal actually supply the value, given upstream validation, types, and auth?
4. **Impact** — does it cross the stated boundary, or is it a style/robustness issue?

Verdicts:

- **confirmed** — all four hold, with `file:line` for the control's absence or failure.
- **needs_validation** — a specific fact is missing (a runtime config, an infra rule, a middleware order). Record that fact as a `question`, and **no severity**.
- **rejected** — keep it in the ledger with the reason, so the next run does not re-report it.

## Step 5 — Severity and fix

Severity comes from reachability × impact, not from the CWE's reputation. Use the rubric in `references/reporting.md`. Default to the lower band when the exploit needs an unlikely precondition, and say which precondition.

Fixes are diffs a maintainer can apply today:

- the **smallest** change that enforces the invariant at the right layer (usually the data layer, not the UI);
- why that layer (what it makes impossible, not just what it blocks);
- the regression test — one assertion that fails before the fix;
- migration/compat note if the fix changes an API or existing rows.

If the correct fix is architectural ("authorize in the query, not in middleware"), say that plainly and give the narrow patch as a stopgap.

## Step 6 — Output

**Quick:** 3–8 lines in chat. Confirmed items first with `file:line` → effect → fix in one sentence each. Then "not an issue" notes for things you checked and cleared that the user is likely to worry about.

**Review:** the same, plus `.security-review/findings.md` when asked, written from `references/reporting.md`'s template.

**Audit:** `findings.json` (schema in `references/reporting.md`), `REPORT.md`, and the coverage ledger. Validate before presenting:

```bash
python3 scripts/validate-findings.py .security-review/findings.json    # exit 1 = do not present yet
```

**Coverage ledger (audit only).** Enumerate boundaries × the classes you considered, and mark each `covered` or `deferred: <reason>`. A boundary that is neither is a hole in the audit, not a clean bill of health. Carry prior ledgers forward: re-check changed source, keep current evidence, never treat a stale `deferred` as covered.

## Anti-patterns that manufacture fake findings

- Reporting a pattern (`eval`, `innerHTML`, `SELECT *` built by f-string) without tracing a principal to an effect.
- Treating a framework default as a vulnerability: React escapes by default; parameterized queries are safe; httpOnly cookies are not readable by JS.
- Flagging the demo/dev/test path as production-reachable.
- "Consider adding rate limiting" with no cost-of-abuse argument. Either name the abuse and the impact, or drop it.
- Severity by keyword: `crypto` → high, `admin` → critical. Severity is reachability × impact.
- Re-reporting last run's rejected candidates without new evidence.
- Pasting a live secret, token, or PII into the report to "prove" it. Reference the location, redact the value.
- Padding the report: ten mediums hide one critical. If you have one real finding, deliver one.

## Done criteria

- [ ] Mode chosen and stated; no artifacts written outside review/audit
- [ ] Packs selected from signals, stated, and ≤4 loaded
- [ ] Trust boundaries written; every boundary either covered or explicitly deferred
- [ ] Every finding has principal, entry point, control gap (`file:line`), effect, severity, fix, regression test
- [ ] Every candidate either confirmed, `needs_validation` with a specific question, or rejected with a reason
- [ ] Greps/scans run (see `references/supply-chain.md` and `scripts/scan.sh`) and reported even when clean
- [ ] No live secret or PII in any output; no live target contacted; no unsandboxed target code executed

## Files

| Path | Read when |
|---|---|
| `references/api-and-injection.md` | injection, SSRF, traversal, upload, mass assignment, headers/CORS |
| `references/auth-and-sessions.md` | authn, sessions/JWT/OAuth, IDOR, tenants, RBAC, middleware |
| `references/client-web.md` | React/Next, Vue/Nuxt, Svelte/SvelteKit: XSS sinks, server→client leaks, actions, tokens, CSP |
| `references/secrets-and-config.md` | env files, client bundles, logs/telemetry, CI, container config |
| `references/supply-chain.md` | lockfiles, install scripts, registry publishing, CI permissions |
| `references/cloud-and-deploy.md` | IAM, buckets, DB exposure, containers, headers, metadata SSRF |
| `references/ai-and-llm.md` | prompts, RAG, tool calling, MCP servers, agent loops |
| `references/server-node.md` | Express, Fastify, Hono, Nest: guard coverage, validation, serialization |
| `references/sql-and-data.md` | Postgres grants/RLS/views, SQLite, MySQL, ORM escape hatches, migrations |
| `references/reporting.md` | severity rubric, `findings.json` schema, report template |
| `scripts/scan.sh` | deterministic secret/dependency/semgrep pass; output only |
| `scripts/validate-findings.py` | schema, dedupe, and evidence gate before presenting |
| `scripts/classify-stack.py` | pack selection from repo signals |

## Attribution

Method (invariant-first hunting, coverage ledger, independent disproof, verdict taxonomy) is adapted from Cloudflare's MIT-licensed `security-audit` skill; framework mappings from OWASP ASVS 5.0, LLM Top 10 (2025), and Agentic Top 10 (2026). See `NOTICE.md`.

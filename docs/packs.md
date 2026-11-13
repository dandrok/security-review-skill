# What the ten packs cover

One pack is read per layer the repo actually has, and never more than four in one review. The full
procedure is in [`../skills/security-review/SKILL.md`](../skills/security-review/SKILL.md).

| Pack | Covers |
|---|---|
| `api-and-injection.md` | SQL/NoSQLi, command injection, traversal and upload, SSRF, SSTI, deserialization, mass assignment, XXE, CORS/CSRF, ReDoS |
| `auth-and-sessions.md` | IDOR/BOLA/BFLA, tenant isolation, Next middleware and server actions, sessions, JWT, OAuth/OIDC, resets/MFA, webhooks |
| `client-web.md` | XSS sinks, sanitizers, CSP, RSC and `+page.server` payload leaks, server and form actions, token storage, postMessage, cache leaks |
| `secrets-and-config.md` | env and committed secrets, client bundles, logs and telemetry, CI, containers, rotation procedure |
| `supply-chain.md` | lockfiles, install scripts, the Shai-Hulud model, provenance/OIDC, CI permissions, publishing |
| `cloud-and-deploy.md` | IAM, buckets, database exposure, containers, edge and serverless, metadata SSRF |
| `ai-and-llm.md` | LLM Top 10 (2025) and Agentic Top 10 (2026), prompt injection, tool use and agency, MCP review, RAG tenancy |
| `server-node.md` | Express middleware order, `trust proxy`, Host header, Fastify schemas and encapsulation, Hono validators, Nest guards / `ValidationPipe` / serialization |
| `sql-and-data.md` | Postgres grants and RLS (`FORCE`, `WITH CHECK`, views), the SQLite file/`ATTACH` model, MySQL notes, ORM escape hatches, migrations, backups |
| `rust-cli.md` | panics as denial of service, allocation ceilings, paths and TOCTOU, `Command` vs `sh -c`, serde depth, terminal escapes, loopback servers, `build.rs` |

`reporting.md` is not a pack: it carries the severity rubric, the `findings.json` schema and the
report template, and is read once before writing findings.

Content is current to late 2026: RSC/server-action authorization (CVE-2025-55182 class), the Next.js
middleware-bypass lesson (CVE-2025-29927), the Shai-Hulud and Mini Shai-Hulud npm worm model, OWASP
LLM Top 10 (2025) and Agentic Top 10 (2026), MCP tool poisoning and rug-pull checks.

# security-review

An agent skill for security reviews that end with **fewer, defensible findings** — not a list of
scary patterns.

Ten reference packs, three deterministic scripts, one folder. Loads into any agent that reads a
skills directory; nothing in it is specific to one tool.

## Contents

1. [Why this exists](#why-this-exists)
2. [What makes it different](#what-makes-it-different)
3. [Install](#install)
4. [Use](#use)
5. [How it works](#how-it-works)
6. [Scope](#scope)
7. [Verify it yourself](#verify-it-yourself)
8. [What it costs in context](#what-it-costs-in-context)
9. [Layout](#layout)
10. [Attribution](#attribution)

## Why this exists

Ask an agent to "security review this" and you get ten plausible findings: `eval`, `innerHTML`, a
missing rate limit, an `any` at a trust boundary. Two are real. You spend a day on the other eight,
then stop reading the output — and the review that was supposed to protect you has taught you to
ignore it. That is the failure this repo is built against: not missing findings, but manufacturing
them.

So the goal is a short report you can act on the same afternoon:

```
1 critical · 2 cleared
- [critical] app/api/invoices/[id]/download/route.ts:22 — any authenticated user of any tenant
  can download any invoice. Fix: add the tenant predicate to the lookup (patch below).
- cleared: JWT verify pins RS256 and rejects alg:none; the session cookie is httpOnly,
  SameSite=Lax, and not readable from JS.
- cleared: the export query is parameterized and scoped by the session workspace, not the body.
```

Every line names a **principal** ("user of another tenant"), a **place** (`route.ts:22`), and the
**control** that should have stopped it. What cannot be written that way is either recorded as
`needs_validation` with the exact missing fact — and no severity — or dropped.

## What makes it different

| Mechanism | What it prevents |
|---|---|
| **Invariant-first hunting** — principal → input → control → path → effect, before anything is written down | findings that are only a pattern match |
| **Disproof pass** — every candidate re-examined with the goal of killing it, optionally by a fresh subagent that never saw how it was found | anything that dies on reachability |
| **Verdict taxonomy** — `confirmed` / `needs_validation` (no severity) / `rejected` (kept with a reason) | padding with guesses, and re-reporting last run's duds |
| **Coverage ledger** (audit mode) — every trust boundary `covered` or `deferred` with a reason | "LGTM, I read six files" |
| **Deterministic scans** — secrets, dependency CVEs, eight offline semgrep rules, plus a coverage line | a "clean" scan that never actually ran |
| **Hard gate** — `validate-findings.py --root` | a `confirmed` with no `file:line`, a citation that does not exist, a line past EOF, a severity on a guess |

## Install

### Let your agent do it

Paste this into the agent you want to use:

> Install the agent skill from `https://github.com/dandrok/security-review-skill`: copy
> `skills/security-review/` into this tool's skills directory, then list your skills to confirm it
> is there.

It worked if the skill appears in that tool's skill list.

### One command, no clone

`gh skill install` knows the layout of every harness in its own list — 48 at GitHub CLI 2.102,
including Copilot, Claude Code, Cursor, Codex, Gemini CLI, Antigravity, OpenCode, Warp, Amp, Goose,
Qwen and `universal`:

```bash
gh skill install dandrok/security-review-skill --agent claude-code
gh skill install dandrok/security-review-skill --agent universal      # anything not listed
```

### Clone and symlink: offline, Hermes, or anything not in the list

Hermes is not in `gh`'s list. Clone once and symlink — `git pull` then updates every agent that
points at it:

```bash
git clone https://github.com/dandrok/security-review-skill
cd security-review-skill
bash install.sh --agent all          # every agent dir it finds
bash install.sh --agent hermes       # or one at a time
bash install.sh --dry-run            # print the plan, change nothing
```

`--copy` copies instead of symlinking, for filesystems where symlinks are awkward or an
agent that refuses to follow one.

### By hand

| Harness | Target |
|---|---|
| Universal / shared | `~/.agents/skills/security-review` — Claude Code, Cursor, Codex, Copilot, Gemini CLI, OpenCode, Antigravity, Warp |
| Claude Code | `~/.claude/skills/security-review`, or `<repo>/.claude/skills/` |
| Antigravity IDE / app | `~/.gemini/config/skills/security-review` |
| Antigravity CLI | `~/.gemini/antigravity-cli/skills/security-review`, or `<workspace>/.agents/skills/` |
| OpenCode | `~/.config/opencode/skills/security-review`, or `<repo>/.opencode/skills/` |
| Hermes | `~/.hermes/skills/software-development/security-review` |
| Project scope | `<repo>/.agents/skills/security-review` |

Four things that bite:

- Antigravity scans **one level deep** — the skill folder must sit directly inside `skills/`.
- A **new** top-level skill directory needs a restart in most tools; Claude Code picks new dirs up live.
- Hermes builds its skill index at session start, so the next session sees it.
- `gitleaks`, `osv-scanner` and `semgrep` are optional and detected at runtime. A missing one is
  reported as skipped — never as clean.

**Requirements:** `bash` and `python3` for the scripts. No Node, no package install, no network.

## Use

The skill triggers on its description, or name it explicitly:

```
review the security of this PR
audit this service — full report
is it safe to store this token in localStorage?
check our MCP server before we publish it
```

| Mode | You asked for | What happens |
|---|---|---|
| quick | a diff, a file, one worry | answer in chat, nothing written |
| review | "security review this" | findings in chat, `.security-review/findings.md` if asked |
| audit | "audit", "full", "pen-test", "report" | `findings.json` + `REPORT.md` + coverage ledger, validated |

Nothing is written and no directory is created unless the mode calls for it.

## How it works

```
Step 1  classify-stack.py   → pick ≤4 packs (this is the whole cost story)
Step 2  map trust boundaries (5–9 lines, no more)
Step 3  run scan.sh, then hunt: principal → input → control → path → effect
Step 4  disprove: reachability, control absence, exploitability, impact
Step 5  severity (reachability × impact) + the smallest fix + the test that would catch it
Step 6  output → validate-findings.py --root → present
```

The packs, and what each one is for:

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

Content is current to late 2026: RSC/server-action authorization (CVE-2025-55182 class), the Next.js
middleware-bypass lesson (CVE-2025-29927), the Shai-Hulud and Mini Shai-Hulud npm worm model, OWASP
LLM Top 10 (2025) and Agentic Top 10 (2026), MCP tool poisoning and rug-pull checks.

## Scope

| | |
|---|---|
| **Strong** | TypeScript/JavaScript web: React and Next, Vue and Nuxt, Svelte and SvelteKit clients; Express, Fastify, Hono and Nest backends; Postgres, SQLite and MySQL; auth, secrets, supply chain, cloud and deploy config; AI/LLM and MCP code |
| **Sinks and shared packs only** | Python (Django/DRF, FastAPI, Flask), Go, PHP, Ruby, Java — the injection sink list and the auth, secrets and supply-chain packs apply; framework-specific authorization semantics are not modelled |
| **Rust** | CLI tools, services and parsers: the real sinks are panics, allocation ceilings, paths, `Command`, serde, terminal escapes, loopback sockets and `build.rs`, with the memory-safety class removed by the language |
| **Not covered** | native and binary code, mobile, embedded, .NET, kernel, or anything that needs exploitation beyond a local proof against dummy data |

## Verify it yourself

The repo ships a deliberately vulnerable fixture, so you can check that the scanners produce real
output instead of decorating this README:

```bash
bash tests/run.sh
```

It builds the fixture, runs `scan.sh`, and asserts that every scanner installed reports, that the
coverage gate goes red when none is, and that the classifier routes the fixture's five packs. The
validator must accept the worked example and reject each bad shape: missing evidence, a control gap
with no line cited, a citation outside the tree, a line past EOF, an unknown coverage id — and exit 2
on a bad `--root`. A scanner that is not installed reports `SKIP`; the suite still exits 0, because
its exit code grades assertions, not scanner coverage.

Prove the *judgement*, not just the plumbing: run this skill and Cloudflare's `security-audit` over
the same known-vulnerable app (OWASP Juice Shop or NodeGoat) and compare confirmed findings. That is
the only claim about quality worth making.

## What it costs in context

Measured with the `o200k` tokenizer, not estimated:

| Part | Tokens | When |
|---|---|---|
| Catalog entry (name + description) | 104 | every turn, always |
| `SKILL.md` body | 3,765 | when the skill triggers |
| One reference pack | 1,494–3,089 | only if the pack is selected |
| All 11 documents at once | ~24,900 | never; routing caps it at 4 |
| `scripts/*` (8,618 total) | **0** | scripts run, their code never enters context — only summary lines do |

A typical review is **~7–16k tokens once** (body plus 2–4 packs), against roughly 55k *per request*
for an equivalent set of eagerly-loaded MCP servers. Loading more packs does not make it smarter:
step 1 exists to load fewer.

For scale, Cloudflare's `security-audit` measures 4,447 tokens for its body and 31,739 across its 14
reference files with the same tokenizer. It is a full-audit instrument for any target type; this one
is 24,900 across 10 packs, aimed at the stacks you actually ship.

## Layout

```
skills/security-review/
├── SKILL.md                  modes, routing, procedure, anti-patterns, done criteria
├── references/               10 packs + severity rubric, findings schema, report template
└── scripts/
    ├── classify-stack.py     repo signals → packs
    ├── scan.sh               gitleaks + osv-scanner + local semgrep (exit 3 = coverage hole)
    ├── validate-findings.py  schema, evidence and citation gate (--root <tree>)
    └── rules/local.yml       8 offline semgrep rules
examples/findings.example.json   worked audit report, valid by construction
tests/run.sh                     end-to-end check of the scripts
install.sh                       per-agent install
```

## Attribution

Method and structure adapted from Cloudflare's
[`security-audit-skill`](https://github.com/cloudflare/security-audit-skill) (MIT, © 2025-2026
Cloudflare, Inc.). Framework mappings reference OWASP ASVS 5.0, OWASP LLM Top 10 (2025), OWASP Top
10 for Agentic Applications (2026) and MITRE CWE — IDs and titles only, no OWASP prose reproduced.

MIT licensed. See [NOTICE.md](NOTICE.md).

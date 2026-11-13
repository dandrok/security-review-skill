# security-review

A portable Agent Skill that turns a coding agent into a security reviewer that **does not hallucinate findings**.

One skill, ten reference packs, three deterministic scripts. Works in Antigravity (IDE + CLI), Claude Code, OpenCode, Codex, Gemini CLI, Cursor, and Hermes — same folder, no rewrite.

## Contents

1. [Why another security skill](#why-another-security-skill)
2. [What it costs in context](#what-it-costs-in-context)
3. [Install](#install)
4. [Use](#use)
5. [How it works](#how-it-works)
6. [Verify it yourself](#verify-it-yourself)
7. [Layout](#layout)
8. [Attribution](#attribution)

## Why another security skill

Most "security review" prompts produce a list of patterns: `eval`, `innerHTML`, missing rate limits. That output looks like work and is mostly wrong — the reviewer then either wastes a day chasing it or learns to ignore the skill.

This skill is built around the opposite goal: **fewer, defensible findings**. Four mechanisms do the work:

| Mechanism | Effect |
|---|---|
| **Invariant-first hunting** — name principal → input → control → path → effect before writing anything | kills "this pattern is scary" findings |
| **Disproof step** — every candidate is re-examined (optionally by a fresh subagent) with the goal of killing it | kills the ones that die on reachability |
| **Verdict taxonomy** — `confirmed` / `needs_validation` / `rejected`, where `needs_validation` carries **no severity** | stops padding with guesses |
| **Coverage ledger** (audit mode) — every trust boundary is `covered` or `deferred` with a reason | stops "LGTM because I read 6 files" |

Plus a hard gate: `scripts/validate-findings.py` refuses a report where a `confirmed` finding has no `file:line` evidence, a `needs_validation` has a severity, or an audit has an uncovered boundary.

Content is current to late 2026: RSC/server-action authz (CVE-2025-55182 class), Next.js middleware bypass lesson (CVE-2025-29927), the Shai-Hulud / Mini Shai-Hulud npm worm model, OWASP LLM Top 10 (2025) and Agentic Top 10 (2026) mappings, MCP tool-poisoning and rug-pull checks.

Method adapted from Cloudflare's MIT-licensed [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill — see [Attribution](#attribution).

## What it costs in context

Measured with the o200k tokenizer, not estimated:

| Part | Tokens | When |
|---|---|---|
| Catalog entry (name + description) | 104 | every turn, always |
| `SKILL.md` body | 3,765 | when the skill triggers |
| One reference pack | 1,494–3,089 | only if the pack is selected |
| All 11 docs at once | ~24,900 | never; the routing step caps it at 4 |
| `scripts/*` (8,618 total) | **0** | scripts run, their code never enters context — only the summary lines |

Typical review: **~7–16k tokens once** (body + 2–4 packs), versus ~55k tokens *per request* for an equivalent set of eagerly-loaded MCP servers. Loading more packs does not make it smarter; step 1 exists to load *fewer*.

For scale: Cloudflare's `security-audit` is 4,447 for its body and 31,739 across its 14 reference files — it is a full-audit instrument for any target type. This one is a third of the surface, aimed at the stacks you actually ship.

## Install

The usual path — one command, it detects your agents and symlinks the skill so `git pull` updates it:

```bash
npx skills add dandrok/security-review-skill                     # pick agents interactively
npx skills add dandrok/security-review-skill -g                  # global, not just this project
npx skills add dandrok/security-review-skill -a claude-code -a antigravity-cli
```

GitHub's own installer does the same without Node (`gh` ≥ 2.102, preview):

```bash
gh skill install dandrok/security-review-skill --agent claude-code
gh skill install dandrok/security-review-skill --agent antigravity-cli
```

Neither of those available? Clone and run the bundled script — it also does every agent in one shot, and its `--dry-run` shows exactly what it would touch:

```bash
git clone https://github.com/dandrok/security-review-skill
cd security-review-skill
bash install.sh --agent all              # symlink into every agent dir it finds
bash install.sh --agent antigravity-cli  # just one
bash install.sh --dry-run                # change nothing, print the plan
```

Manual (any agent, one line each):

| Agent | Target dir |
|---|---|
| Antigravity CLI (global) | `~/.gemini/antigravity-cli/skills/security-review` |
| Antigravity CLI (workspace) | `.agents/skills/security-review` |
| Antigravity IDE/app | `~/.gemini/config/skills/security-review` |
| Claude Code | `~/.claude/skills/security-review` (or `.claude/skills/` in a repo) |
| OpenCode | `~/.config/opencode/skills/security-review` (or `.opencode/skills/`) |
| Universal / shared | `~/.agents/skills/security-review` (Claude Code, Cursor, Codex, Copilot, Gemini CLI, OpenCode, Antigravity, Warp…) |
| Hermes | `~/.hermes/skills/software-development/security-review` |

Or install through GitHub's CLI, which knows every agent's layout:

```bash
gh skill install dandrok/security-review-skill --agent antigravity-cli
gh skill install dandrok/security-review-skill --agent claude-code
```
Notes:

- Antigravity scans **one level deep**: the skill folder must sit directly inside `skills/`.
- Antigravity CLI and Gemini CLI both read `.agents/skills/` and `~/.gemini/skills/`.
- Claude Code watches skill dirs live; a *new* top-level dir needs a restart.
- Hermes builds its skill index at session start — a new session picks it up.
- Optional scanners (`gitleaks`, `osv-scanner`, `semgrep`) are detected at runtime. Missing ones are reported as skipped, never as clean.

- `npx skills` collects anonymous install telemetry by default; `DISABLE_TELEMETRY=1` opts out.
- Whichever route you use, the whole folder goes with it — `references/` and `scripts/` are what make the packs and the scanners work.
## Use

The skill triggers on the description; you can also invoke it explicitly.

```
review the security of this PR
audit this service — full report
is it safe to store this token in localStorage?
check our MCP server before we publish it
```

Modes:

| Mode | You asked for | What happens |
|---|---|---|
| quick | a diff, a file, one worry | answer in chat, no files written |
| review | "security review this" | findings in chat + `.security-review/findings.md` if asked |
| audit | "audit", "full", "pen-test", "report" | `findings.json` + `REPORT.md` + coverage ledger, validated |

Nothing is written and no directory is created unless the mode calls for it.

## How it works

```
Step 1  classify-stack.py  → pick ≤4 packs (the whole cost story is here)
Step 2  map trust boundaries (5–9 lines)
Step 3  hunt: principal → input → control → path → effect
Step 4  disprove: reachability, control absence, exploitability, impact
Step 5  severity (reachability × impact) + smallest fix + regression test
Step 6  output → validate-findings.py → present
```

Packs:

| Pack | Covers |
|---|---|
| `api-and-injection.md` | SQL/NoSQLi, command injection, traversal/upload, SSRF, SSTI, deserialization, mass assignment, XXE, CORS/CSRF, ReDoS |
| `auth-and-sessions.md` | IDOR/BOLA/BFLA, tenant isolation, Next middleware + server actions, sessions, JWT, OAuth/OIDC, resets/MFA, webhooks |
| `client-web.md` | XSS sinks, sanitizers, CSP, RSC and `+page.server` payload leaks, server actions/form actions, token storage, postMessage, cache leaks |
| `secrets-and-config.md` | env/committed secrets, client bundles, logs/telemetry, CI, containers, rotation procedure |
| `supply-chain.md` | lockfiles, install scripts, Shai-Hulud model, provenance/OIDC, CI permissions, publishing |
| `cloud-and-deploy.md` | IAM, buckets, DB exposure, containers, edge/serverless, metadata SSRF |
| `ai-and-llm.md` | LLM Top 10 2025 + Agentic Top 10 2026, prompt injection, tools/agency, MCP review, RAG tenancy |
| `server-node.md` | Express middleware order + `trust proxy` + Host header, Fastify schemas/encapsulation, Hono validators, Nest guards / `ValidationPipe` / serialization |
| `sql-and-data.md` | Postgres grants + RLS (`FORCE`, `WITH CHECK`, views), SQLite file/`ATTACH` model, MySQL notes, ORM escape hatches, migrations, backups |

## Verify it yourself

The repo ships a deliberately vulnerable fixture so you can check the scanners produce real output instead of decorating the README:

```bash
bash tests/run.sh          # builds the fixture, runs scan.sh, asserts each scanner reports;
                           # a scanner that is not installed reports SKIP, not FAIL
```

Expected on this fixture: 1 secret, 5 dependency advisories, 3 local-rule hits, validator rejects the bad sample and accepts the good one. With a scanner missing, that row reads `SKIP` and `bash tests/run.sh` still exits 0 — the exit code reports grading, not scanner coverage.

Prove the skill's *judgement*, not just its plumbing: run it and Cloudflare's `security-audit` over the same known-vulnerable app (OWASP Juice Shop or NodeGoat) and compare confirmed findings. That's the only claim about quality worth making.

## Layout

```
skills/security-review/
├── SKILL.md                  modes, routing, procedure, anti-patterns, done criteria
├── references/               10 packs + severity rubric, schema, report template
└── scripts/
    ├── classify-stack.py     repo signals → packs
    ├── scan.sh               gitleaks + osv-scanner + local semgrep (exit 3 = coverage hole)
    ├── validate-findings.py  schema/evidence/citation gate (`--root <tree>`)
    └── rules/local.yml       8 offline semgrep rules
examples/findings.example.json   worked audit report, valid by construction
tests/run.sh                     end-to-end check of the scripts
install.sh                       per-agent install
```

## Attribution

Method and structure adapted from Cloudflare's [`security-audit-skill`](https://github.com/cloudflare/security-audit-skill) (MIT, © 2025-2026 Cloudflare, Inc.). Framework mappings reference OWASP ASVS 5.0, OWASP LLM Top 10 (2025), OWASP Top 10 for Agentic Applications (2026), and MITRE CWE — IDs and titles only, no OWASP prose reproduced.

MIT licensed. See [NOTICE.md](NOTICE.md).

# security-review

An agent skill that turns a coding agent into a security reviewer whose findings you can act on:
each one names a principal, a reachable entry point, and the control that should have stopped it.

Ten reference packs, three deterministic scripts, one folder. Works in any agent that reads a skills
directory; nothing in it is specific to one tool.

[Why](#why-this-exists) · [Install](#install) · [Use](#use) · [Verify](#verify-it-yourself) ·
[Scope](#scope) · [Cost](#what-it-costs-in-context) · [Files](#files)

## Why this exists

Ask an agent to "security review this" and you get ten plausible findings: `eval`, `innerHTML`, a
missing rate limit. Two are real. You spend a day on the other eight, then stop reading the output —
and the review that was supposed to protect you has taught you to ignore it. This skill is built
against that failure: not missing findings, but manufacturing them.

So the output is short and checkable:

```
1 critical · 2 cleared
- [critical] app/api/invoices/[id]/download/route.ts:22 — any authenticated user of any tenant
  can download any invoice. Fix: tenant predicate in the lookup (patch below).
- cleared: JWT verify pins RS256 and rejects alg:none; the session cookie is httpOnly/SameSite=Lax.
- cleared: the export query is parameterized and scoped by the session workspace, not the body.
```

What cannot be written that way is recorded as `needs_validation` — with the exact missing fact and
no severity — or dropped.

## What makes it different

| Mechanism | What it prevents |
|---|---|
| **Invariant-first hunting** — principal → input → control → path → effect, before anything is written | findings that are only a pattern match |
| **Disproof pass** — every candidate re-examined with the goal of killing it, optionally by a fresh subagent | anything that dies on reachability |
| **Verdict taxonomy** — `confirmed` / `needs_validation` (no severity) / `rejected` (kept with a reason) | padding, and re-reporting last run's duds |
| **Coverage ledger** — every trust boundary `covered` or `deferred` with a reason (audit mode) | "LGTM, I read six files" |
| **Deterministic scans** — secrets, dependency CVEs, eight offline semgrep rules, plus a coverage line | a "clean" scan that never ran |
| **Hard gate** — `validate-findings.py --root` | a "confirmed" with no `file:line`, a citation that does not exist, severity on a guess |

## Install

Paste this at your agent — it copies `skills/security-review/` into that tool's skills directory, then
confirms it is there:

> Install the agent skill from `https://github.com/dandrok/security-review-skill`, then list your
> skills to confirm it is there.

Deterministic alternatives:

```bash
gh skill install dandrok/security-review-skill --agent claude-code   # 48 harness layouts at CLI 2.102
gh skill install dandrok/security-review-skill --agent universal     # anything not listed

git clone https://github.com/dandrok/security-review-skill           # offline, or Hermes (not in gh's list)
cd security-review-skill && bash install.sh --agent all
```

Per-harness paths, project scope, and the four things that surprise people:
[docs/install.md](docs/install.md). Needs `bash` and `python3`; no Node, no package install, no
network.

## Use

```
review the security of this PR
audit this service — full report
is it safe to store this token in localStorage?
```

| Mode | Ask for it with | What happens |
|---|---|---|
| quick | a diff, a file, one worry | answer in chat, nothing written |
| review | "security review this" | findings in chat, `.security-review/findings.md` if asked |
| audit | "audit", "full", "pen-test", "report" | `findings.json` + `REPORT.md` + coverage ledger, validated |

Nothing is written and no directory is created unless the mode calls for it.

## Verify it yourself

```bash
bash tests/run.sh
```

It builds a deliberately vulnerable fixture and asserts that every installed scanner reports, that the
coverage gate goes red when none is, and that the classifier routes the fixture's five packs. The
validator must accept the worked example and reject each bad shape — missing evidence, uncited control
gap, citation outside the tree, line past EOF, unknown coverage id — and exit 2 on a bad `--root`. A
scanner that is not installed reports `SKIP` and the suite still exits 0: its exit code grades
assertions, not scanner coverage.

Prove the judgement, not the plumbing: run this skill and Cloudflare's `security-audit` over the same
known-vulnerable app (Juice Shop, NodeGoat) and compare confirmed findings. That is the only claim
about quality worth making.

## Scope

| | |
|---|---|
| **Strong** | TypeScript/JavaScript web — React, Next, Vue, Nuxt, Svelte, SvelteKit clients; Express, Fastify, Hono, Nest backends; Postgres, SQLite, MySQL; auth, secrets, supply chain, cloud and deploy config; AI/LLM and MCP code |
| **Rust** | CLI tools, services, parsers: panics as DoS, allocation ceilings, paths, `Command`, serde, terminal escapes, loopback sockets, `build.rs` |
| **Sinks and shared packs only** | Python (Django/DRF, FastAPI, Flask), Go, PHP, Ruby, Java — the injection sink list and the auth, secrets and supply-chain packs apply; framework-specific authorization semantics are not modelled |
| **Not covered** | native and binary code, mobile, embedded, .NET, kernel, or anything needing exploitation beyond a local proof against dummy data |

## What it costs in context

| Part | Tokens | When |
|---|---|---|
| Catalog entry (name + description) | 104 | every turn, always |
| `SKILL.md` body | 3,765 | when the skill triggers |
| One reference pack | 1,494–3,089 | only if the pack is selected |
| All 11 documents at once | ~24,900 | never; routing caps it at 4 |
| `scripts/*` (8,618 total) | **0** | scripts run, their code never enters context |

Measured with the `o200k` tokenizer. A typical review is **~7–16k tokens once** (body plus 2–4 packs),
against ~55k *per request* for an equivalent set of eagerly-loaded MCP servers — loading more packs
does not make it smarter, which is why step 1 exists to load fewer. Cloudflare's `security-audit`
measures 4,447 (body) and 31,739 (14 reference files) the same way, as a full-audit instrument for any
target type; this one is 24,900 across 10 packs for the stacks you ship.

## Files

```
skills/security-review/SKILL.md     the procedure: routing, boundaries, hunting, output, anti-patterns
skills/security-review/references/  10 packs + severity rubric, schema, report template → docs/packs.md
skills/security-review/scripts/     classify-stack.py, scan.sh, validate-findings.py, rules/local.yml
examples/findings.example.json      a worked audit report, valid by construction
tests/run.sh                        end-to-end check of the scripts
install.sh                          per-agent install (symlink or --copy)
```

## Licence

MIT — see [LICENSE](LICENSE). Method and structure adapted from Cloudflare's MIT-licensed
[`security-audit-skill`](https://github.com/cloudflare/security-audit-skill); framework mappings
reference OWASP ASVS 5.0, OWASP LLM Top 10 (2025), Agentic Top 10 (2026) and MITRE CWE — IDs and
titles only, no OWASP prose reproduced. Full attribution in [NOTICE.md](NOTICE.md).

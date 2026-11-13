# Pack: Severity, schema, and reporting

Read this once, immediately before writing findings in **review** or **audit** mode. It is the output contract; `scripts/validate-findings.py` enforces the machine-checkable parts.

## Severity rubric

Score two axes and take the lower band when either is weak. Do not score by CWE reputation.

**Reachability** — how easily the named principal gets there:

| | Meaning |
|---|---|
| **E** | unauthenticated, internet-facing, default config, no user interaction |
| **A** | any authenticated user, or one click, or a normal feature path |
| **C** | requires another user's cooperation, a privileged role, a non-default config, or a race |

**Impact** — what crossing the boundary yields:

| | Meaning |
|---|---|
| **1** | code execution, full tenant/account takeover, mass data read, credential theft, payment manipulation |
| **2** | single-record data access, privilege step-up within the app, stored XSS on authenticated pages, auth bypass on one route |
| **3** | information disclosure with limited value, DoS of one user, CSRF on a low-value action |
| **4** | hardening gaps, defence-in-depth, best-practice deviations with no demonstrated effect |

| Impact \ Reachability | E | A | C |
|---|---|---|---|
| 1 | **critical** | high | medium |
| 2 | high | medium | low |
| 3 | medium | low | low |
| 4 | low | info | info |

Rules: `needs_validation` has **no severity** — the missing fact decides it. Never inflate a band to get attention; an audit full of highs gets read as noise and the real critical is missed. State the precondition that keeps it out of a higher band.

## Verdicts

| Verdict | Required to hold |
|---|---|
| `confirmed` | entry point reachable, control absent (or provably wrong) with `file:line`, principal can supply the input, effect crosses the named boundary |
| `needs_validation` | one specific fact is missing and named as a `question`; no severity, no fix marked as final |
| `rejected` | kept with a reason — prevents re-reporting next run |

## `findings.json`

```json
{
  "schema_version": "1.0",
  "target": {"name": "acme-web", "revision": "git:4f2a1c9", "scope": ["apps/web", "packages/api"]},
  "mode": "review",
  "generated_at": "2026-10-31T12:00:00Z",
  "packs": ["client-web", "auth-and-sessions"],
  "findings": [
    {
      "id": "SR-001",
      "verdict": "confirmed",
      "title": "Any authenticated user can read another tenant's invoice PDF",
      "severity": "critical",
      "confidence": "high",
      "cwe": ["CWE-639", "CWE-284"],
      "owasp": ["A01:2021", "API1:2023"],
      "principal": "authenticated user of tenant B",
      "boundary": "tenant isolation",
      "entry_point": "GET /api/invoices/:id/download (app/api/invoices/[id]/download/route.ts:14)",
      "control_gap": "handler loads the invoice by id only; no tenantId predicate and no ownership check before signing the URL (route.ts:22-27)",
      "effect": "returns a signed download URL for any invoice id, including other tenants'",
      "reproduction": "1. sign in as tenant B user 2. request tenant A invoice id 3. receive a valid URL",
      "evidence": [
        {"file": "app/api/invoices/[id]/download/route.ts", "line": 22, "note": "findUnique({ where: { id } })"}
      ],
      "fix": {
        "summary": "scope the lookup to the session tenant and add a regression test",
        "diff_or_patch": "- const inv = await db.invoice.findUnique({ where: { id } })\n+ const inv = await db.invoice.findFirst({ where: { id, tenantId: session.tenantId } })\n+ if (!inv) return NextResponse.json({ error: 'not found' }, { status: 404 })",
        "test": "test: tenant B requesting tenant A invoice id returns 404 and no URL"
      },
      "notes": "404 (not 403) avoids confirming existence"
    }
  ],
  "coverage": [
    {"boundary": "tenant isolation", "class": "object-level authz", "status": "covered", "finding_ids": ["SR-001"]},
    {"boundary": "public API → DB", "class": "sql injection", "status": "covered", "finding_ids": []},
    {"boundary": "webhook in", "class": "signature/replay", "status": "deferred", "reason": "provider is selected by the client at runtime; config not in repo"}
  ]
}
```

Field rules:

- `id` — `SR-<n>`, stable across runs; the same finding keeps its id.
- `cwe` — array, real CWE ids only (`CWE-79`, `CWE-639`). Prefer the most specific.
- `evidence` — at least one `file`+`line` for `confirmed`. No evidence, no `confirmed`. With `--root <tree>` the file must exist there and the line must be inside it: a citation the reader cannot open is a guess, and the validator treats it as one.
- `control_gap` — must carry a `file:line` (or `file:a-b`) for `confirmed`. "No check exists" is a claim about a place; without a line it is an impression.
- `reproduction` — steps, not a payload dump; no live target, no real secret.
- `fix.diff_or_patch` — the minimal change. Never a full-file rewrite.
- `coverage` — audit mode only; every boundary from Step 2 appears as `covered` or `deferred` with a reason. A missing row is an audit hole.

## Redaction

Before writing: strip live secret values (keep `sk_live_…` prefix + length), customer PII, and internal hostnames that are themselves sensitive. Quote code, not credentials. If a fix requires showing a value, show the shape (`process.env.STRIPE_SECRET`), never the content.

## `REPORT.md` template

Follow the reader's preference: a contents list with jump links, short sections, findings in severity order, and a back-to-contents link after each.

```markdown
# Security review — <target> @ <revision>

**Scope:** <paths> · **Mode:** review · **Date:** <date>
**Result:** <n> confirmed (<crit>/<high>/<med>/<low>), <n> needs validation, <n> rejected

## Contents
1. [Summary](#summary)
2. [Findings](#findings)
3. [Needs validation](#needs-validation)
4. [Checked and clean](#checked-and-clean)
5. [Coverage ledger](#coverage-ledger)   <!-- audit mode -->
6. [Method](#method)

## Summary
- two to four bullets: what an owner must do first, and why
- one line on what was NOT reviewed

## Findings

### SR-001 — <title> · **crit** · CWE-639
`file:line` · principal · boundary
**What happens:** effect in one sentence.
**How:** control gap with the cited lines.
**Fix:** the diff. **Test:** one line.
[↑ contents](#contents)

## Needs validation
| id | question | why it blocks a verdict |
|---|---|---|
[↑ contents](#contents)

## Checked and clean
Categories examined and cleared, one line each — this is what stops the reader
re-reporting the same non-issues, and it is evidence the review had coverage.

## Coverage ledger
| boundary | class | status |
|---|---|---|
[↑ contents](#contents)

## Method
Packs loaded, scans run (`gitleaks`, `osv-scanner`, `semgrep`) with the coverage line (`n/3 scanners reported`, and what was skipped, missing or errored),
limits (read-only source, no live targets, sandboxed), and the revision reviewed.
```

## Chat output (quick mode)

```
1 critical · 1 high · 2 cleared
- [critical] app/api/invoices/[id]/download/route.ts:22 — any tenant can download any invoice. Fix: add tenantId to the lookup (patch below).
- [high] lib/markdown.ts:8 — rehype-raw without a sanitizer, user HTML executes. Fix: drop rehype-raw or gate on DOMPurify.
- cleared: JWT verify pins RS256; session cookie is httpOnly/SameSite=Lax.
```

Three to eight lines. No preamble, no methodology essay. If there is nothing, say "no confirmed issues in the paths reviewed" plus what was *not* covered — never "the app is secure".

## Before presenting

```bash
python3 scripts/validate-findings.py .security-review/findings.json --root .
```

Exit 1 means: schema violation, missing evidence on a `confirmed`, a `control_gap` with no line cited, severity on a `needs_validation`, duplicate id, an uncovered boundary, a coverage row naming a finding that does not exist, or — with `--root` — an evidence file that is not in the tree or a line past the end of it. Fix the report, do not present it anyway.

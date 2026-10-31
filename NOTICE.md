# NOTICE

## Adapted work

The workflow in `skills/security-review/SKILL.md` — invariant-first hunting,
the coverage ledger, independent disproof of candidates, and the
confirmed / needs_validation / rejected verdict taxonomy — is adapted from:

  cloudflare/security-audit-skill
  https://github.com/cloudflare/security-audit-skill
  Copyright (c) 2025-2026 Cloudflare, Inc.
  MIT License

The reference packs here are written for a different target profile (TypeScript /
React / Next.js / Node web applications and freelance client projects) and are not
a copy of Cloudflare's hunting classes. Where their text informed a rule, the rule
was rewritten; no file is a verbatim copy.

## Standards referenced

Identifiers, category names, and titles from the following are cited. No prose from
these documents is reproduced.

- OWASP Application Security Verification Standard (ASVS) 5.0
- OWASP Top 10 for Large Language Model Applications (2025)
- OWASP Top 10 for Agentic Applications (2026), OWASP Gen AI Security Project
- OWASP Agentic Skills Top 10 (AST10)
- MITRE Common Weakness Enumeration (CWE)

## Tools invoked, not bundled

`gitleaks` (MIT), `osv-scanner` (Apache-2.0), and `semgrep` (LGPL-2.1) are called if
present on `PATH`. None are vendored, none are installed by this skill, and nothing
is downloaded at review time. The eight rules in `scripts/rules/local.yml` are
original and run fully offline.

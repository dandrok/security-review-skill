#!/usr/bin/env python3
"""Gate a findings.json before it is presented.

Enforces the contract in references/reporting.md: evidence on every confirmed finding,
no severity on needs_validation, valid severity/CWE values, unique ids, and (audit mode)
a coverage row for every boundary.

Usage:
    python3 scripts/validate-findings.py .security-review/findings.json [--json] [--quiet]

Exit codes: 0 = clean, 1 = violations, 2 = unreadable input.
"""

from __future__ import annotations

import json
import re
import sys

SEV = {"critical", "high", "medium", "low", "info"}
VERDICTS = {"confirmed", "needs_validation", "rejected"}
CWE_RE = re.compile(r"^CWE-\d{1,4}$")
REQUIRED = ["id", "verdict", "title"]

# Fields a finding must carry to be actionable, by verdict.
REQUIRED_BY_VERDICT = {
    "confirmed": ["severity", "principal", "boundary", "entry_point", "control_gap",
                  "effect", "evidence", "fix"],
    "needs_validation": ["principal", "boundary", "question"],
    "rejected": ["rejection_reason"],
}


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate(doc: dict) -> list[str]:
    errs: list[str] = []
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return ["`findings` must be a list"]

    seen: set[str] = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errs.append(f"{where}: must be an object")
            continue

        fid = f.get("id") or where
        for key in REQUIRED:
            if not f.get(key):
                errs.append(f"{fid}: missing `{key}`")
        if fid in seen:
            errs.append(f"{fid}: duplicate id")
        seen.add(fid)

        verdict = f.get("verdict")
        if verdict not in VERDICTS:
            errs.append(f"{fid}: verdict must be one of {sorted(VERDICTS)}")
            continue

        for key in REQUIRED_BY_VERDICT.get(verdict, []):
            if not f.get(key):
                errs.append(f"{fid}: {verdict} requires `{key}`")

        if verdict == "needs_validation" and "severity" in f:
            errs.append(f"{fid}: needs_validation must not carry a severity (the missing fact decides it)")

        if verdict == "confirmed":
            if f.get("severity") not in SEV:
                errs.append(f"{fid}: severity must be one of {sorted(SEV)}")
            ev = f.get("evidence") or []
            if not isinstance(ev, list) or not ev:
                errs.append(f"{fid}: confirmed requires at least one evidence entry")
            else:
                for j, e in enumerate(ev):
                    if not isinstance(e, dict) or not e.get("file") or not isinstance(e.get("line"), int):
                        errs.append(f"{fid}: evidence[{j}] needs `file` and integer `line`")
            fix = f.get("fix")
            if isinstance(fix, dict):
                if not fix.get("summary"):
                    errs.append(f"{fid}: fix needs a `summary`")
                if not (fix.get("diff_or_patch") or fix.get("test")):
                    errs.append(f"{fid}: fix needs a `diff_or_patch` or a `test`")
            elif fix is not None and not isinstance(fix, str):
                errs.append(f"{fid}: fix must be an object or string")
            if not f.get("reproduction"):
                # a confirmed finding the reader cannot re-check is a guess
                errs.append(f"{fid}: confirmed requires `reproduction` steps")

        for cwe in f.get("cwe") or []:
            if not CWE_RE.match(str(cwe)):
                errs.append(f"{fid}: bad cwe `{cwe}` (expected CWE-<number>)")

        if f.get("confidence") and f.get("confidence") not in {"high", "medium", "low"}:
            errs.append(f"{fid}: confidence must be high|medium|low")

    coverage = doc.get("coverage")
    if doc.get("mode") == "audit":
        if not isinstance(coverage, list) or not coverage:
            errs.append("audit mode requires a non-empty `coverage` ledger")
        else:
            for i, c in enumerate(coverage):
                if c.get("status") not in {"covered", "deferred"}:
                    errs.append(f"coverage[{i}]: status must be covered|deferred")
                if c.get("status") == "deferred" and not c.get("reason"):
                    errs.append(f"coverage[{i}]: deferred needs a `reason`")
    return errs


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: validate-findings.py <findings.json> [--json] [--quiet]", file=sys.stderr)
        return 2
    try:
        doc = load(args[0])
    except Exception as exc:  # unreadable / invalid JSON
        print(f"FATAL: cannot read {args[0]}: {exc}", file=sys.stderr)
        return 2

    errs = validate(doc)
    findings = doc.get("findings") or []
    by_verdict: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        by_verdict[f.get("verdict", "?")] = by_verdict.get(f.get("verdict", "?"), 0) + 1
        if f.get("severity"):
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    if "--json" in sys.argv:
        print(json.dumps({"ok": not errs, "errors": errs,
                          "counts": {"verdicts": by_verdict, "severity": by_sev}}, indent=2))
    elif "--quiet" not in sys.argv:
        total = len(findings)
        print(f"{total} finding(s): " + ", ".join(f"{k}={v}" for k, v in sorted(by_verdict.items())))
        if by_sev:
            print("severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
        if errs:
            print(f"\n{len(errs)} violation(s):")
            for e in errs:
                print(f"  - {e}")
        else:
            print("\nOK — schema, evidence, and severity rules satisfied.")

    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())

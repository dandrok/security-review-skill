#!/usr/bin/env python3
"""Gate a findings.json before it is presented.

Enforces the contract in references/reporting.md: evidence on every confirmed finding,
no severity on needs_validation, valid severity/CWE values, unique ids, a control gap
that cites a line, coverage rows that point at real findings and, with --root, evidence
that actually exists in the reviewed tree at the line it claims.

Usage:
    python3 scripts/validate-findings.py .security-review/findings.json [--root <repo>] [--json] [--quiet]

Exit codes: 0 = clean, 1 = violations, 2 = unreadable input.

--root is the tree that was reviewed. Without it the citation check is schema-only, so a
report can still cite a file that does not exist; pass it in audit mode and whenever the
findings are going to a reader who will try to open the lines.
"""

from __future__ import annotations

import json
import os
import re
import sys

SEV = {"critical", "high", "medium", "low", "info"}
VERDICTS = {"confirmed", "needs_validation", "rejected"}
CWE_RE = re.compile(r"^CWE-\d{1,4}$")
LINE_CITE_RE = re.compile(r":\d+")
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


def line_count(path: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for _ in fh)


def check_evidence(root: str, fid: str, ev: list, errs: list[str]) -> None:
    """Every cited file and line must exist in the tree that was reviewed."""
    real_root = os.path.realpath(root)
    for j, e in enumerate(ev):
        if not isinstance(e, dict) or not e.get("file"):
            continue
        rel = str(e["file"])
        path = os.path.realpath(os.path.join(real_root, rel))
        if not (path == real_root or path.startswith(real_root + os.sep)):
            errs.append(f"{fid}: evidence[{j}] escapes --root: {rel}")
            continue
        if not os.path.isfile(path):
            errs.append(f"{fid}: evidence[{j}] file not found under --root: {rel}")
            continue
        n = line_count(path)
        line = e.get("line")
        if isinstance(line, int) and not (1 <= line <= max(n, 1)):
            errs.append(f"{fid}: evidence[{j}] line {line} is outside {rel} (1..{n})")


def validate(doc: dict, root: str | None = None) -> list[str]:
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
            gap = str(f.get("control_gap") or "")
            if gap and not LINE_CITE_RE.search(gap):
                # "no check anywhere" is a claim about a place; without a line it is a guess
                errs.append(f"{fid}: control_gap must cite a line (`file:line`)")
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

        if root:
            ev = f.get("evidence")
            if isinstance(ev, list) and ev:
                check_evidence(root, str(fid), ev, errs)

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
                for fid in c.get("finding_ids") or []:
                    if fid not in seen:
                        errs.append(f"coverage[{i}]: finding_ids names `{fid}`, which is not in findings")
    return errs


def parse_args(argv: list[str]) -> tuple[str | None, str | None, bool, bool, str | None]:
    path = root = None
    as_json = quiet = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--root":
            i += 1
            root = argv[i] if i < len(argv) else None
            if root is None:
                return None, None, False, False, "--root needs a path"
        elif arg == "--json":
            as_json = True
        elif arg == "--quiet":
            quiet = True
        elif arg.startswith("-"):
            return None, None, False, False, f"unknown option: {arg}"
        elif path is None:
            path = arg
        else:
            return None, None, False, False, f"unexpected argument: {arg}"
        i += 1
    if root and not os.path.isdir(root):
        return None, None, False, False, f"--root is not a directory: {root}"
    return path, root, as_json, quiet, None


def main() -> int:
    path, root, as_json, quiet, arg_err = parse_args(sys.argv[1:])
    if arg_err or not path:
        print(arg_err or __doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: validate-findings.py <findings.json> [--root <repo>] [--json] [--quiet]",
              file=sys.stderr)
        return 2
    try:
        doc = load(path)
    except Exception as exc:  # unreadable / invalid JSON
        print(f"FATAL: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    errs = validate(doc, root)
    findings = doc.get("findings") or []
    by_verdict: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        by_verdict[f.get("verdict", "?")] = by_verdict.get(f.get("verdict", "?"), 0) + 1
        if f.get("severity"):
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    if as_json:
        print(json.dumps({"ok": not errs, "errors": errs,
                          "counts": {"verdicts": by_verdict, "severity": by_sev}}, indent=2))
    elif not quiet:
        total = len(findings)
        print(f"{total} finding(s): " + ", ".join(f"{k}={v}" for k, v in sorted(by_verdict.items())))
        if by_sev:
            print("severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
        print(f"citation root: {os.path.abspath(root) if root else 'not checked (pass --root <repo>)'}")
        if errs:
            print(f"\n{len(errs)} violation(s):")
            for e in errs:
                print(f"  - {e}")
        else:
            print("\nOK — schema, evidence, citations, and severity rules satisfied.")

    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())

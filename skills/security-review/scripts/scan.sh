#!/usr/bin/env bash
# Deterministic scan pass: secrets, dependency CVEs, local semgrep rules.
#
# Design: results go to files. Only counts and paths come back to the caller, so a
# 500-finding JSON blob never enters a model's context.
#
# Graceful: a missing scanner is reported as "skipped" and the rest still runs.
# Exit code: 0 always, unless --strict (then 1 if any scanner reported findings).
#
# Usage:
#   bash scripts/scan.sh [--dir .] [--out .security-review/scans] [--strict] [--skip gitleaks,osv]

set -u

DIR="."
OUT=""
STRICT=0
SKIP=""

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--dir) DIR="${2:-}"; shift 2 ;;
    -o|--out) OUT="${2:-}"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --skip) SKIP="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -d "$DIR" ] || { echo "error: no such directory: $DIR" >&2; exit 2; }
[ -n "$OUT" ] || OUT="$DIR/.security-review/scans"
mkdir -p "$OUT" || { echo "error: cannot create $OUT" >&2; exit 2; }

skipped_by_user() { case ",$SKIP," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

RAN=""
FINDINGS=0
REPORT="$OUT/scan-summary.json"

note() { printf '%s\n' "$*"; }

run_gitleaks() {
  local bin out err
  bin="$(command -v gitleaks || true)"
  [ -n "$bin" ] || { note "gitleaks    : skipped (not installed)"; return; }
  skipped_by_user gitleaks && { note "gitleaks    : skipped (--skip)"; return; }
  out="$OUT/gitleaks.json"
  err="$OUT/gitleaks.err"
  rm -f "$out"
  # v8.19+ : gitleaks dir ; older: gitleaks detect --no-git
  # NOTE: gitleaks exits 1 when it FINDS something. Judge by the report, not the exit code.
  "$bin" dir "$DIR" --report-format json --report-path "$out" --no-banner -l error >/dev/null 2>"$err"
  if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
    rm -f "$out"
    "$bin" detect --no-git -s "$DIR" --report-format json -r "$out" --no-banner -l error >/dev/null 2>>"$err"
  fi
  if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
    note "gitleaks    : failed (see $err)"
    return
  fi
  local n
  n=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(len(d) if isinstance(d,list) else 0)
" "$out" 2>/dev/null || echo "?")
  note "gitleaks    : ${n} potential secret(s) -> $out"
  RAN="$RAN gitleaks"
  [ "$n" != "?" ] && [ "$n" -gt 0 ] 2>/dev/null && FINDINGS=$((FINDINGS+n))
  return 0
}

run_osv() {
  local bin out log rc
  bin="$(command -v osv-scanner || true)"
  [ -n "$bin" ] || { note "osv-scanner : skipped (not installed)"; return; }
  skipped_by_user osv && { note "osv-scanner : skipped (--skip)"; return; }
  out="$OUT/osv.json"
  log="$OUT/osv.log"
  rm -f "$out"
  # v2 subcommand form, then v1 flag-only form. osv-scanner exits non-zero when it
  # finds vulnerabilities or when there is nothing to scan: judge by the report + log.
  "$bin" scan source -r "$DIR" --format json --output-file "$out" >"$log" 2>&1
  rc=$?
  if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
    if grep -qi "no package sources" "$log" 2>/dev/null || grep -qi "no lockfile" "$log" 2>/dev/null; then
      note "osv-scanner : no dependency sources found (no lockfile in scope)"
      return
    fi
    rm -f "$out"
    "$bin" -r "$DIR" --format json >"$out" 2>>"$log"
    if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      note "osv-scanner : failed rc=$rc (see $log)"
      return
    fi
  fi
  local n
  n=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
ids=set()
for r in d.get('results',[]) or []:
    for p in r.get('packages',[]) or []:
        for g in p.get('groups',[]) or []:
            for i in g.get('ids',[]) or []:
                ids.add(i)
    for v in r.get('vulnerabilities',[]) or []:
        ids.add(v.get('id'))
print(len(ids))
" "$out" 2>/dev/null || echo "?")
  note "osv-scanner : ${n} advisory hit(s) -> $out"
  RAN="$RAN osv"
  [ "$n" != "?" ] && [ "$n" -gt 0 ] 2>/dev/null && FINDINGS=$((FINDINGS+n))
  return 0
}

run_semgrep() {
  local bin out
  bin="$(command -v semgrep || true)"
  [ -n "$bin" ] || { note "semgrep     : skipped (not installed; see README)"; return; }
  skipped_by_user semgrep && { note "semgrep     : skipped (--skip)"; return; }
  out="$OUT/semgrep.json"
  local rules
  rules="$(cd "$(dirname "$0")" && pwd)/rules"
  if [ ! -d "$rules" ]; then
    note "semgrep     : skipped (local rules missing at $rules)"
    return
  fi
  if ! "$bin" scan --config "$rules" --json --quiet --metrics=off --disable-version-check \
        --exclude node_modules --exclude .git --exclude dist --exclude .next \
        "$DIR" >"$out" 2>"$OUT/semgrep.err"; then
    # semgrep exits 1 when it has findings, which is fine; anything else is a failure
    if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      note "semgrep     : failed (see $OUT/semgrep.err)"
      return
    fi
  fi
  local n
  n=$(python3 -c "
import json,sys
print(len(json.load(open(sys.argv[1])).get('results',[])))
" "$out" 2>/dev/null || echo "?")
  note "semgrep     : ${n} local-rule hit(s) -> $out"
  RAN="$RAN semgrep"
  [ "$n" != "?" ] && [ "$n" -gt 0 ] 2>/dev/null && FINDINGS=$((FINDINGS+n))
  return 0
}

note "scan target : $(cd "$DIR" && pwd)"
note "output      : $(cd "$OUT" && pwd)"
note ""

run_gitleaks
run_osv
run_semgrep

python3 - "$REPORT" "$DIR" "$OUT" "$RAN" <<'PY'
import json, os, sys, datetime
report, target, out, ran = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split()
counts = {}
for name in ran:
    path = os.path.join(out, f"{name}.json")
    try:
        data = json.load(open(path))
    except Exception:
        counts[name] = None
        continue
    if name == "gitleaks":
        counts[name] = len(data) if isinstance(data, list) else None
    elif name == "semgrep":
        counts[name] = len(data.get("results", []))
    else:
        ids = set()
        for r in data.get("results", []) or []:
            for p in r.get("packages", []) or []:
                for g in p.get("groups", []) or []:
                    for i in g.get("ids", []) or []:
                        ids.add(i)
            for v in r.get("vulnerabilities", []) or []:
                ids.add(v.get("id"))
        counts[name] = len(ids)
json.dump({
    "target": os.path.abspath(target),
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "scanners_run": ran,
    "counts": counts,
    "files": sorted(os.listdir(out)),
}, open(report, "w"), indent=2)
PY

note ""
note "summary     : $REPORT"
note ""
note "Next: triage every hit by reachability. A hit is not a finding."
note "  - secrets  -> references/secrets-and-config.md (live? in history? rotate first)"
note "  - deps     -> references/supply-chain.md (is the vulnerable path used?)"
note "  - rules    -> confirm the sink has attacker-reachable input, then trace the effect"

if [ "$STRICT" -eq 1 ] && [ "$FINDINGS" -gt 0 ]; then
  exit 1
fi
exit 0

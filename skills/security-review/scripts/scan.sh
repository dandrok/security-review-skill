#!/usr/bin/env bash
# Deterministic scan pass: secrets, dependency CVEs, local semgrep rules.
#
# Design: results go to files. Only counts and paths come back to the caller, so a
# 500-finding JSON blob never enters a model's context.
#
# Graceful: a missing scanner is reported as "skipped" and the rest still runs.
# A skipped, errored or absent scanner is a COVERAGE HOLE, not a clean result:
# the coverage line is printed on every run and --strict refuses to exit 0 without it.
#
# Exit codes:
#   0  completed at the coverage available (read the coverage line, not the code)
#   1  --strict: at least one scanner reported findings
#   2  usage error
#   3  --strict: coverage incomplete (a scanner errored, or fewer than three
#      reported). A deliberate --skip counts as covered; nothing installed does not.
#
# Usage:
#   bash scripts/scan.sh [--dir .] [--out .security-review/scans] [--strict] [--skip gitleaks,osv]

set -u

DIR="."
OUT=""
STRICT=0
SKIP=""
EXPECTED=3

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--dir) DIR="${2:-}"; shift 2 ;;
    -o|--out) OUT="${2:-}"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --skip) SKIP="${2:-}"; shift 2 ;;
    -h|--help) awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -d "$DIR" ] || { echo "error: no such directory: $DIR" >&2; exit 2; }
[ -n "$OUT" ] || OUT="$DIR/.security-review/scans"
mkdir -p "$OUT" || { echo "error: cannot create $OUT" >&2; exit 2; }
# A previous run's report must not be read as this run's evidence.
rm -f "$OUT"/gitleaks.json "$OUT"/gitleaks.err \
      "$OUT"/osv.json "$OUT"/osv.log \
      "$OUT"/semgrep.json "$OUT"/semgrep.err \
      "$OUT"/scan-summary.json

skipped_by_user() { case ",$SKIP," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

RAN=""
MISSING=""
FAILED=""
USERSKIP=""
N_RAN=0
N_FAILED=0
N_USERSKIP=0
FINDINGS=0
REPORT="$OUT/scan-summary.json"

note() { printf '%s\n' "$*"; }
ran_ok() { RAN="$RAN $1"; N_RAN=$((N_RAN+1)); }
not_installed() { MISSING="$MISSING $1"; }
errored() { FAILED="$FAILED $1"; N_FAILED=$((N_FAILED+1)); }
user_skip() { USERSKIP="$USERSKIP $1"; N_USERSKIP=$((N_USERSKIP+1)); }

run_gitleaks() {
  local bin out err
  skipped_by_user gitleaks && { note "gitleaks    : skipped (--skip)"; user_skip gitleaks; return; }
  bin="$(command -v gitleaks || true)"
  [ -n "$bin" ] || { note "gitleaks    : skipped (not installed)"; not_installed gitleaks; return; }
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
    errored gitleaks
    return
  fi
  local n
  n=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(len(d) if isinstance(d,list) else 0)
" "$out" 2>/dev/null || echo "?")
  note "gitleaks    : ${n} potential secret(s) -> $out"
  ran_ok gitleaks
  [ "$n" != "?" ] && [ "$n" -gt 0 ] 2>/dev/null && FINDINGS=$((FINDINGS+n))
  return 0
}

run_osv() {
  local bin out log rc
  skipped_by_user osv && { note "osv-scanner : skipped (--skip)"; user_skip osv; return; }
  bin="$(command -v osv-scanner || true)"
  [ -n "$bin" ] || { note "osv-scanner : skipped (not installed)"; not_installed osv; return; }
  out="$OUT/osv.json"
  log="$OUT/osv.log"
  rm -f "$out"
  # v2 subcommand form, then v1 flag-only form. osv-scanner exits non-zero when it
  # finds vulnerabilities or when there is nothing to scan: judge by the report + log.
  "$bin" scan source -r "$DIR" --format json --output-file "$out" >"$log" 2>&1
  rc=$?
  if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
    if grep -qi "no package sources" "$log" 2>/dev/null || grep -qi "no lockfile" "$log" 2>/dev/null; then
      # It ran and settled the question: there is nothing to look up.
      note "osv-scanner : no dependency sources found (no lockfile in scope)"
      ran_ok osv
      return
    fi
    rm -f "$out"
    "$bin" -r "$DIR" --format json >"$out" 2>>"$log"
    if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      note "osv-scanner : failed rc=$rc (see $log)"
      errored osv
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
  ran_ok osv
  [ "$n" != "?" ] && [ "$n" -gt 0 ] 2>/dev/null && FINDINGS=$((FINDINGS+n))
  return 0
}

run_semgrep() {
  local bin out
  skipped_by_user semgrep && { note "semgrep     : skipped (--skip)"; user_skip semgrep; return; }
  bin="$(command -v semgrep || true)"
  [ -n "$bin" ] || { note "semgrep     : skipped (not installed; see README)"; not_installed semgrep; return; }
  out="$OUT/semgrep.json"
  local rules
  rules="$(cd "$(dirname "$0")" && pwd)/rules"
  if [ ! -d "$rules" ]; then
    # The skill installs its own rules; not finding them is a broken install, not a clean run.
    note "semgrep     : failed (local rules missing at $rules)"
    errored semgrep
    return
  fi
  if ! "$bin" scan --config "$rules" --json --quiet --metrics=off --disable-version-check \
        --exclude node_modules --exclude .git --exclude dist --exclude .next \
        "$DIR" >"$out" 2>"$OUT/semgrep.err"; then
    # semgrep exits 1 when it has findings, which is fine; anything else is a failure
    if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      note "semgrep     : failed (see $OUT/semgrep.err)"
      errored semgrep
      return
    fi
  fi
  local n
  n=$(python3 -c "
import json,sys
print(len(json.load(open(sys.argv[1])).get('results',[])))
" "$out" 2>/dev/null || echo "?")
  note "semgrep     : ${n} local-rule hit(s) -> $out"
  ran_ok semgrep
  [ "$n" != "?" ] && [ "$n" -gt 0 ] 2>/dev/null && FINDINGS=$((FINDINGS+n))
  return 0
}

note "scan target : $(cd "$DIR" && pwd)"
note "output      : $(cd "$OUT" && pwd)"
note ""

run_gitleaks
run_osv
run_semgrep

# Coverage, not exit code, is the thing to report. A --skip is a deliberate choice a
# reader can see; a missing binary or a crash is a hole nobody sees unless it is named.
COVERED=$((N_RAN + N_USERSKIP))
COMPLETE=1
if [ "$COVERED" -ne "$EXPECTED" ]; then COMPLETE=0; fi
if [ "$N_FAILED" -gt 0 ]; then COMPLETE=0; fi

COVLINE="coverage    : ${COVERED}/${EXPECTED} scanners reported"
[ -n "$FAILED" ] && COVLINE="$COVLINE | errored:$FAILED"
[ -n "$MISSING" ] && COVLINE="$COVLINE | not installed:$MISSING"
[ -n "$USERSKIP" ] && COVLINE="$COVLINE | skipped by --skip:$USERSKIP"
note ""
note "$COVLINE"
if [ "$COMPLETE" -ne 1 ]; then
  note "WARNING     : coverage incomplete — do not report this scan as clean; name what did not run"
fi

python3 - "$REPORT" "$DIR" "$OUT" "$RAN" "$MISSING" "$FAILED" "$USERSKIP" "$COMPLETE" <<'PY'
import json, os, sys, datetime
report, target, out, ran, missing, failed, userskip, complete = sys.argv[1:9]
ran, missing, failed, userskip = ran.split(), missing.split(), failed.split(), userskip.split()
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
    "coverage": {
        "expected": 3,
        "ran": ran,
        "errored": failed,
        "not_installed": missing,
        "skipped": userskip,
        "complete": complete == "1",
    },
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
note "  - coverage -> --strict exits 3 when a scanner was missing or errored; that is a hole, not a pass"

if [ "$STRICT" -eq 1 ]; then
  if [ "$FINDINGS" -gt 0 ]; then exit 1; fi
  if [ "$COMPLETE" -ne 1 ]; then exit 3; fi
fi
exit 0

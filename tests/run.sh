#!/usr/bin/env bash
# End-to-end check of the skill's scripts against a deliberately vulnerable fixture.
# Asserts the scanners actually report, the coverage gate bites, the validator gates
# citations, and the classifier routes correctly. No target code executed.
#
# A scanner that is not installed reports SKIP and does not fail the run: the exit code
# grades the assertions, never the scanner coverage. Coverage has its own check, which
# forces the missing path with an empty PATH.
#
# Usage: bash tests/run.sh

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$REPO/skills/security-review"
# Guard before any rm -rf: REPO comes from the script path, and an empty result here
# would turn the trap below into a delete outside the tree.
[ -n "$REPO" ] && [ -d "$REPO/skills" ] || { echo "error: cannot locate the repo root" >&2; exit 2; }
WORK="$REPO/tests/.tmp"
rm -rf "$WORK"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT
FIX="$WORK/fixture-vuln-app"

PASS=0
FAIL=0
SKIP=0

ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skp()  { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
check(){ if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }

# PATH holding the tools scan.sh needs and none of the scanners, so the
# "nothing installed" path is forced rather than inherited from this machine.
BARE="$WORK/bare"
mkdir -p "$BARE"
for b in bash python3 sh grep sed cat mkdir rm ls dirname; do
  src="$(command -v "$b" 2>/dev/null || true)"
  [ -n "$src" ] && ln -sf "$src" "$BARE/$b"
done

have_scanner() {
  # a mise/asdf shim resolves but exits non-zero when no version is configured
  command -v "$1" >/dev/null 2>&1 || return 1
  "$1" --version >/dev/null 2>&1 && return 0
  "$1" version >/dev/null 2>&1
}

mkdir -p "$FIX/app/api/invoices/[id]" "$FIX/app/invoices"

cat > "$FIX/package.json" <<'EOF'
{ "name": "fixture", "private": true,
  "dependencies": { "next": "15.2.2", "react": "19.0.0", "lodash": "4.17.20", "jsonwebtoken": "9.0.0" } }
EOF

cat > "$FIX/package-lock.json" <<'EOF'
{ "name": "fixture", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
  "packages": { "": { "name": "fixture", "dependencies": { "lodash": "4.17.20" } },
    "node_modules/lodash": { "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" } } }
EOF

cat > "$FIX/app/api/invoices/[id]/route.ts" <<'EOF'
export async function POST(req: Request) {
  const body = await req.json();
  const { execSync } = require("child_process");
  execSync(`pdftk ${body.file} output ${body.out}`);
  const token = require("jsonwebtoken").decode(body.token);
  return Response.json({ token });
}
EOF

cat > "$FIX/app/invoices/view.tsx" <<'EOF'
export default function V({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
EOF

# stack signals for the v1.1 packs
echo '{"collection":"@nestjs/schematics"}' > "$FIX/nest-cli.json"
mkdir -p "$FIX/src/users" "$FIX/prisma"
printf 'import { Controller } from "@nestjs/common";\n@Controller("users")\nexport class UsersController {}\n' > "$FIX/src/users/users.controller.ts"
printf 'datasource db {\n  provider = "postgresql"\n}\n' > "$FIX/prisma/schema.prisma"
printf 'CREATE POLICY tenant_isolation ON invoices USING (true);\n' > "$FIX/prisma/001_init.sql"

# The fixture key is assembled at runtime on purpose: a literal provider-shaped
# string in this repo would trip GitHub push protection and gitleaks-on-this-repo.
# The value is synthetic and authenticates nowhere.
FIXTURE_KEY_PREFIX='sk_'
FIXTURE_KEY_BODY='live_51HxQ2eKZ9mPqR7tYvW3nB8dL4jF6gH0sA2cD5e'
printf 'NEXT_PUBLIC_STRIPE_SECRET_KEY=%s%s\n' "$FIXTURE_KEY_PREFIX" "$FIXTURE_KEY_BODY" > "$FIX/.env.local"

echo "== classify-stack =="
OUT=$(python3 "$SKILL/scripts/classify-stack.py" "$FIX")
echo "$OUT" | grep -q "references/api-and-injection.md"; check $? "selects api pack"
echo "$OUT" | grep -q "references/client-web.md";         check $? "selects client-web pack"
echo "$OUT" | grep -q "references/server-node.md";        check $? "selects server-node pack (nest signals)"
echo "$OUT" | grep -q "references/sql-and-data.md";       check $? "selects sql-and-data pack (prisma/sql)"

# Rust: a Cargo manifest and crate names must route to the rust pack.
RUST="$WORK/fixture-rust"
mkdir -p "$RUST/src"
cat > "$RUST/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.1.0"

[dependencies]
axum = "0.8"
rusqlite = "0.41"
EOF
printf 'fn main() {}\n' > "$RUST/src/main.rs"
OUT=$(python3 "$SKILL/scripts/classify-stack.py" "$RUST")
echo "$OUT" | grep -q "references/rust-cli.md";  check $? "selects rust-cli pack (Cargo.toml + *.rs)"
echo "$OUT" | grep -q "crates: .*axum";          check $? "routes axum to the api pack"
echo "$OUT" | grep -q "crates: .*rusqlite";      check $? "routes rusqlite to the data pack"

# Routing must not fire on substrings or on agent config. `**/*rag*` matched
# "Average.js"; `.claude/agents/*.md` is a skill file, not an LLM surface.
KATAS="$WORK/fixture-katas"
mkdir -p "$KATAS/src/javascript" "$KATAS/.claude/agents"
printf 'module.exports = 1\n' > "$KATAS/src/javascript/Average.js"
printf '{"name":"katas","private":true,"dependencies":{}}\n' > "$KATAS/package.json"
printf '{"lockfileVersion":3,"packages":{}}\n' > "$KATAS/package-lock.json"
printf '# reviewer agent\n' > "$KATAS/.claude/agents/reviewer.md"
OUT=$(python3 "$SKILL/scripts/classify-stack.py" "$KATAS")
echo "$OUT" | grep -q "ai-and-llm"; [ $? -ne 0 ]; check $? "Average.js and .claude/agents do not route to the ai pack"
echo "$OUT" | grep -q "supply-chain"; check $? "katas fixture still routes the lockfile"

# Positive control for the same pack: a real RAG dir and an MCP module must still route.
AISURF="$WORK/fixture-ai"
mkdir -p "$AISURF/src/rag" "$AISURF/src/llm/prompts"
printf 'export const q = 1\n' > "$AISURF/src/rag/query.ts"
printf 'export const s = 1\n' > "$AISURF/src/mcp.ts"
printf 'system prompt\n' > "$AISURF/src/llm/prompts/system.md"
OUT=$(python3 "$SKILL/scripts/classify-stack.py" "$AISURF")
echo "$OUT" | grep -q "ai-and-llm"; check $? "a real rag dir and mcp module do route to the ai pack"

echo "== scan.sh =="
SCAN_OUT=$(bash "$SKILL/scripts/scan.sh" --dir "$FIX" 2>&1)
if have_scanner gitleaks; then
  echo "$SCAN_OUT" | grep -Eq "gitleaks *: [1-9]"; check $? "gitleaks reports a secret"
else
  # Two unavailable states, both of which must be reported rather than passed over:
  # no binary at all, or a version-manager shim that resolves and then exits non-zero.
  if echo "$SCAN_OUT" | grep -q "gitleaks *: skipped (not installed)"; then
    ok "gitleaks absent and reported as skipped"
  elif echo "$SCAN_OUT" | grep -Eq "gitleaks *: failed"; then
    ok "unusable gitleaks reported as failed, not skipped"
  else
    bad "gitleaks is unavailable but scan.sh did not say so"
  fi
  echo "$SCAN_OUT" | grep -Eq "coverage    : [0-2]/3"
  check $? "an unavailable gitleaks appears in the coverage line"
  skp "gitleaks not usable here — secret detection not exercised"
fi
if have_scanner osv-scanner; then
  if echo "$SCAN_OUT" | grep -q "osv-scanner *: failed"; then
    skp "osv-scanner could not reach the OSV API (offline or no lockfile in scope)"
  else
    echo "$SCAN_OUT" | grep -Eq "osv-scanner *: ([1-9]|no dependency sources)"; check $? "osv-scanner reports advisories"
  fi
else
  if echo "$SCAN_OUT" | grep -q "osv-scanner *: skipped (not installed)"; then
    ok "osv-scanner absent and reported as skipped"
  else
    echo "$SCAN_OUT" | grep -Eq "osv-scanner *: failed"
    check $? "unusable osv-scanner reported as failed, not skipped"
  fi
  skp "osv-scanner not usable here — dependency CVEs not exercised"
fi
if have_scanner semgrep; then
  echo "$SCAN_OUT" | grep -Eq "semgrep *: [1-9]"; check $? "semgrep reports rule hits"
else
  if echo "$SCAN_OUT" | grep -q "semgrep *: skipped (not installed"; then
    ok "semgrep absent and reported as skipped"
  else
    echo "$SCAN_OUT" | grep -Eq "semgrep *: failed"
    check $? "unusable semgrep reported as failed, not skipped"
  fi
  skp "semgrep not usable here — local rules not exercised"
fi
echo "$SCAN_OUT" | grep -q "^coverage    :"; check $? "prints a coverage line on every run"

echo "== scan.sh coverage gate =="
# Exit 0 is a claim about assertions, so the gate has to be forced: no scanners on PATH.
BARE_OUT=$(env PATH="$BARE" bash "$SKILL/scripts/scan.sh" --dir "$FIX" 2>&1); BARE_RC=$?
[ "$BARE_RC" -eq 0 ]; check $? "no scanners, no --strict: exits 0"
echo "$BARE_OUT" | grep -q "coverage    : 0/3"; check $? "no scanners: coverage line says 0/3"
echo "$BARE_OUT" | grep -q "WARNING"; check $? "no scanners: warns that this is not a clean scan"

env PATH="$BARE" bash "$SKILL/scripts/scan.sh" --dir "$FIX" --strict >/dev/null 2>&1; STRICT_RC=$?
[ "$STRICT_RC" -eq 3 ]; check $? "no scanners, --strict: exits 3 (coverage hole), not 0"

env PATH="$BARE" bash "$SKILL/scripts/scan.sh" --dir "$FIX" --strict --skip gitleaks,osv,semgrep >/dev/null 2>&1; SKIP_RC=$?
[ "$SKIP_RC" -eq 0 ]; check $? "--skip on all three: exits 0 (deliberate omission is covered)"

# A scanner that is installed and crashes is a hole, not a pass.
STUB="$WORK/stub"
mkdir -p "$STUB"
cat > "$STUB/gitleaks" <<'EOF'
#!/bin/sh
echo "simulated gitleaks failure" >&2
exit 2
EOF
chmod +x "$STUB/gitleaks"
ERR_OUT=$(env PATH="$STUB:$BARE" bash "$SKILL/scripts/scan.sh" --dir "$FIX" --strict 2>&1); ERR_RC=$?
[ "$ERR_RC" -eq 3 ]; check $? "a crashing scanner under --strict exits 3"
echo "$ERR_OUT" | grep -Eq "errored: *gitleaks"; check $? "coverage line names the errored scanner"

echo "== validate-findings =="
python3 "$SKILL/scripts/validate-findings.py" "$REPO/examples/findings.example.json" --quiet
check $? "accepts the example report"
python3 "$SKILL/scripts/validate-findings.py" "$REPO/tests/fixtures/bad-findings.json" --quiet >/dev/null 2>&1
[ $? -eq 1 ]; check $? "rejects the invalid report"

# --root must prove the citations exist, so build the tree the example cites.
ROOT="$WORK/cited-root"
mkdir -p "$ROOT/app/api/invoices/[id]/download" "$ROOT/components" "$ROOT/app/api/export" "$ROOT/packages/api/src"
pad() { n="$2"; i=1; : > "$1"; while [ "$i" -le "$n" ]; do echo "// line $i" >> "$1"; i=$((i+1)); done; }
pad "$ROOT/app/api/invoices/[id]/download/route.ts" 40
pad "$ROOT/components/Markdown.tsx" 20
pad "$ROOT/app/api/export/route.ts" 40
pad "$ROOT/packages/api/src/scope.ts" 20
python3 "$SKILL/scripts/validate-findings.py" "$REPO/examples/findings.example.json" --root "$ROOT" --quiet
check $? "accepts the example when --root holds every cited line"

mkdir -p "$WORK/empty-root"
python3 "$SKILL/scripts/validate-findings.py" "$REPO/examples/findings.example.json" --root "$WORK/empty-root" --quiet >/dev/null 2>&1
[ $? -eq 1 ]; check $? "rejects citations that are not in --root"

python3 - "$REPO/examples/findings.example.json" "$WORK" <<'PY'
import json, sys
src, out = sys.argv[1], sys.argv[2]
doc = json.load(open(src))

def dump(name, mut):
    d = json.loads(json.dumps(doc))
    mut(d)
    json.dump(d, open(f"{out}/{name}", "w"))

def past_eof(d):
    d["findings"][0]["evidence"][0]["line"] = 999

def no_line(d):
    d["findings"][0]["control_gap"] = "the handler loads the invoice by id only"

def ghost_id(d):
    d["coverage"][0]["finding_ids"] = ["SR-001", "SR-404"]

dump("bad-line.json", past_eof)
dump("bad-gap.json", no_line)
dump("bad-coverage.json", ghost_id)
PY
python3 "$SKILL/scripts/validate-findings.py" "$WORK/bad-line.json" --root "$ROOT" --quiet >/dev/null 2>&1
[ $? -eq 1 ]; check $? "rejects an evidence line past the end of the file"
python3 "$SKILL/scripts/validate-findings.py" "$WORK/bad-gap.json" --quiet >/dev/null 2>&1
[ $? -eq 1 ]; check $? "rejects a confirmed control_gap with no line cited"
python3 "$SKILL/scripts/validate-findings.py" "$WORK/bad-coverage.json" --quiet >/dev/null 2>&1
[ $? -eq 1 ]; check $? "rejects a coverage row naming a finding that does not exist"
python3 "$SKILL/scripts/validate-findings.py" "$REPO/examples/findings.example.json" --root >/dev/null 2>&1
[ $? -eq 2 ]; check $? "--root without a path is a usage error (exit 2)"

echo
echo "passed: $PASS  failed: $FAIL  skipped: $SKIP"
[ "$FAIL" -eq 0 ] || exit 1

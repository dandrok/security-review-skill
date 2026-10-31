#!/usr/bin/env bash
# End-to-end check of the skill's scripts against a deliberately vulnerable fixture.
# Asserts the scanners actually report, the validator gates correctly, and the
# classifier selects packs. No network beyond the OSV API; no target code executed.
#
# Usage: bash tests/run.sh

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$REPO/skills/security-review"
FIX="$(mktemp -d)/fixture-vuln-app"
PASS=0
FAIL=0

ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
check(){ if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }

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

echo "== scan.sh =="
SCAN=$(bash "$SKILL/scripts/scan.sh" --dir "$FIX" 2>&1)
echo "$SCAN" | grep -Eq "gitleaks *: [1-9]";  check $? "gitleaks reports a secret"
echo "$SCAN" | grep -Eq "osv-scanner *: [1-9]"; check $? "osv-scanner reports advisories"
echo "$SCAN" | grep -Eq "semgrep *: [1-9]";     check $? "semgrep reports rule hits"

echo "== scan.sh --strict =="
bash "$SKILL/scripts/scan.sh" --dir "$FIX" --strict >/dev/null 2>&1
[ $? -eq 1 ]; check $? "strict mode exits 1 when findings exist"

echo "== validate-findings =="
python3 "$SKILL/scripts/validate-findings.py" "$REPO/examples/findings.example.json" --quiet
check $? "accepts the example report"
python3 "$SKILL/scripts/validate-findings.py" "$REPO/tests/fixtures/bad-findings.json" --quiet >/dev/null 2>&1
[ $? -eq 1 ]; check $? "rejects the invalid report"

echo
echo "passed: $PASS  failed: $FAIL"
rm -rf "$(dirname "$FIX")"
[ "$FAIL" -eq 0 ] || exit 1

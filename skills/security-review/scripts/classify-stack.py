#!/usr/bin/env python3
"""Pick the reference packs that apply to this repo.

Prints detected stacks and the packs to read. Deterministic, stdlib only, no network,
read-only. Exit code is always 0 unless the path is invalid.

Usage:
    python3 scripts/classify-stack.py [path] [--json]
"""

from __future__ import annotations

import json
import os
import sys

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".output",
    "vendor", ".venv", "venv", "__pycache__", ".turbo", "coverage", ".cache",
    "target", ".svelte-kit", "out", ".parcel-cache",
}

# signal -> (pack, human label)
SIGNALS = {
    "references/client-web.md": [
        ("*.tsx", "React/TSX components"),
        ("*.jsx", "React/JSX components"),
        ("*.vue", "Vue components"),
        ("*.svelte", "Svelte components"),
        ("svelte.config.*", "SvelteKit"),
        ("nuxt.config.*", "Nuxt"),
        ("**/+page.server.ts", "SvelteKit server load/actions"),
        ("**/+server.ts", "SvelteKit endpoints"),
        ("next.config.*", "Next.js"),
        ("vite.config.*", "Vite"),
        ("**/+layout.server.ts", "SvelteKit server layout"),
        ("src/App.tsx", "React SPA"),
        ("app/**/page.tsx", "Next App Router"),
        ("pages/**/*.tsx", "Next Pages Router"),
    ],
    "references/api-and-injection.md": [
        ("**/route.ts", "Next route handlers"),
        ("**/routes/**", "routes directory"),
        ("**/controllers/**", "controllers"),
        ("**/handlers/**", "handlers"),
        ("**/api/**", "API directory"),
        ("server.js", "Node server"),
        ("manage.py", "Django"),
        ("**/main.go", "Go service"),
        ("**/*.graphql", "GraphQL schema"),
    ],
    "references/auth-and-sessions.md": [
        ("middleware.ts", "Next middleware"),
        ("**/auth/**", "auth module"),
        ("**/login*", "login route"),
        ("**/session*", "session module"),
        ("**/jwt*", "JWT handling"),
        ("**/oauth*", "OAuth"),
    ],
    "references/server-node.md": [
        ("nest-cli.json", "NestJS"),
        ("**/*.module.ts", "Nest module"),
        ("**/*.guard.ts", "Nest guard"),
        ("**/*.controller.ts", "Nest controller"),
        ("server.ts", "Node server entry"),
        ("app.ts", "Node app entry"),
    ],
    "references/sql-and-data.md": [
        ("**/schema.prisma", "Prisma schema"),
        ("drizzle.config.*", "Drizzle"),
        ("knexfile.*", "Knex"),
        ("**/*.sql", "SQL files"),
        ("**/migrations/**", "migrations"),
        ("supabase/**", "Supabase"),
        ("*.db", "SQLite file"),
        ("*.sqlite", "SQLite file"),
    ],
    "references/secrets-and-config.md": [
        (".env*", "env files present"),
        ("Dockerfile", "Dockerfile"),
        ("docker-compose*.yml", "compose"),
        ("**/logger.*", "logger"),
        ("**/sentry.*", "error tracking"),
    ],
    "references/supply-chain.md": [
        ("package-lock.json", "npm lockfile"),
        ("pnpm-lock.yaml", "pnpm lockfile"),
        ("yarn.lock", "yarn lockfile"),
        ("uv.lock", "uv lockfile"),
        ("poetry.lock", "poetry lockfile"),
        ("requirements.txt", "requirements.txt"),
        (".github/workflows/*", "GitHub Actions"),
        ("**/action.yml", "composite action"),
    ],
    "references/cloud-and-deploy.md": [
        ("*.tf", "Terraform"),
        ("**/k8s/**", "k8s manifests"),
        ("**/helm/**", "Helm"),
        ("serverless.yml", "serverless"),
        ("fly.toml", "Fly.io"),
        ("vercel.json", "Vercel"),
        ("netlify.toml", "Netlify"),
        ("**/nginx.conf", "nginx"),
        ("cdk.json", "AWS CDK"),
    ],
    "references/ai-and-llm.md": [
        ("**/prompts/**", "prompts directory"),
        ("**/agents/**", "agent code"),
        ("**/tools/**", "tool definitions"),
        ("mcp.json", "MCP config"),
        ("**/mcp*.{json,ts,py}", "MCP server"),
        ("**/*embedding*", "embeddings"),
        ("**/*rag*", "RAG"),
    ],
}


# Framework names in a manifest -> pack. Filenames lie: a Svelte or Nest repo can
# look like plain TypeScript until you read the dependencies.
DEP_SIGNALS = {
    "references/client-web.md": {
        "react", "react-dom", "next", "vue", "nuxt", "svelte", "@sveltejs/kit",
        "vite", "@remix-run/react", "gatsby", "astro",
    },
    "references/server-node.md": {
        "express", "fastify", "hono", "@nestjs/core", "koa", "@trpc/server",
    },
    "references/sql-and-data.md": {
        "drizzle-orm", "drizzle-kit", "prisma", "@prisma/client", "knex", "typeorm",
        "sequelize", "@supabase/supabase-js", "pg", "mysql2", "better-sqlite3",
        "sqlite3", "@libsql/client",
    },
    "references/auth-and-sessions.md": {
        "jsonwebtoken", "jose", "next-auth", "@auth/core", "passport", "lucia",
        "better-auth", "@clerk/nextjs", "express-session", "@fastify/jwt",
    },
    "references/ai-and-llm.md": {
        "openai", "@anthropic-ai/sdk", "langchain", "@modelcontextprotocol/sdk",
        "ai", "@ai-sdk/openai", "llamaindex",
    },
}
PY_DEP_SIGNALS = {
    "django": "references/api-and-injection.md",
    "djangorestframework": "references/api-and-injection.md",
    "fastapi": "references/api-and-injection.md",
    "flask": "references/api-and-injection.md",
    "sqlalchemy": "references/sql-and-data.md",
    "psycopg2": "references/sql-and-data.md",
    "psycopg2-binary": "references/sql-and-data.md",
    "asyncpg": "references/sql-and-data.md",
}


def read_deps(root: str) -> set[str]:
    """Dependency names from package.json, requirements.txt, pyproject.toml."""
    import json
    import re as _re

    names: set[str] = set()
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg):
        try:
            data = json.load(open(pkg, encoding="utf-8"))
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                names.update(data.get(key) or {})
        except Exception:
            pass
    for req in ("requirements.txt", "requirements-dev.txt"):
        path = os.path.join(root, req)
        if os.path.isfile(path):
            try:
                for line in open(path, encoding="utf-8", errors="ignore"):
                    line = line.strip().lower()
                    m = _re.match(r"^([a-z0-9._-]+)", line)
                    if m and not line.startswith("#"):
                        names.add(m.group(1))
            except Exception:
                pass
    py = os.path.join(root, "pyproject.toml")
    if os.path.isfile(py):
        try:
            text = open(py, encoding="utf-8", errors="ignore").read().lower()
            for dep in PY_DEP_SIGNALS:
                if f'"{dep}' in text or f"'{dep}" in text:
                    names.add(dep)
        except Exception:
            pass
    return names


PACK_ALWAYS = "references/reporting.md"


def walk(root: str, limit: int = 20000) -> list[str]:
    """Relative paths, bounded, skipping vendor dirs."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            out.append(rel)
            if len(out) >= limit:
                return out
    return out


def match(path: str, pattern: str) -> bool:
    import fnmatch

    # Support **/ by trying the path and every suffix at a segment boundary.
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.startswith("**/"):
        rest = pattern[3:]
        parts = path.split(os.sep)
        for i in range(len(parts)):
            if fnmatch.fnmatch(os.sep.join(parts[i:]), rest):
                return True
    if "/" in pattern:
        parts = path.split(os.sep)
        for i in range(len(parts)):
            if fnmatch.fnmatch(os.sep.join(parts[i:]), pattern):
                return True
    return False


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    root = args[0] if args else "."
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    files = walk(root)
    deps = read_deps(root)
    # Cheap size guard for big trees
    found: dict[str, list[str]] = {}
    for pack, sigs in SIGNALS.items():
        hits: list[str] = []
        for pattern, label in sigs:
            n = sum(1 for f in files if match(f, pattern))
            if n:
                hits.append(f"{label} ({n})")
        dep_hits = sorted(d for d in deps if d in DEP_SIGNALS.get(pack, set()))
        if dep_hits:
            hits.append("deps: " + ", ".join(dep_hits))
        if hits:
            found[pack] = hits

    packs = sorted(found, key=lambda p: -len(found[p]))

    if as_json:
        print(json.dumps({
            "root": os.path.abspath(root),
            "files_scanned": len(files),
            "packs": {p: found[p] for p in packs},
            "always": PACK_ALWAYS,
            "recommended": packs[:4],
        }, indent=2))
        return 0

    print(f"Scanned {len(files)} files in {os.path.abspath(root)}\n")
    if not found:
        print("No stack signals found. Read references/api-and-injection.md only if the")
        print("repo exposes a network interface, otherwise work from SKILL.md alone.")
        return 0

    print("Detected:")
    for pack in packs:
        print(f"  {pack}")
        for h in found[pack]:
            print(f"      - {h}")

    print("\nRead at most 4, highest signal first:")
    for pack in packs[:4]:
        print(f"  {pack}")
    if len(packs) > 4:
        print(f"  (over the 4-pack cap: {', '.join(p.split('/')[-1] for p in packs[4:])})")
    print(f"\nAlways: {PACK_ALWAYS}")
    print("\nState the selection in one line before hunting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
    "references/client-react.md": [
        ("*.tsx", "React/TSX components"),
        ("*.jsx", "React/JSX components"),
        ("next.config.*", "Next.js"),
        ("vite.config.*", "Vite"),
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
    # Cheap size guard for big trees
    found: dict[str, list[str]] = {}
    for pack, sigs in SIGNALS.items():
        hits: list[str] = []
        for pattern, label in sigs:
            n = sum(1 for f in files if match(f, pattern))
            if n:
                hits.append(f"{label} ({n})")
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
        print(f"  (skipping {', '.join(p.split('/')[-1] for p in packs[4:])} — no signal strong enough)")
    print(f"\nAlways: {PACK_ALWAYS}")
    print("\nState the selection in one line before hunting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

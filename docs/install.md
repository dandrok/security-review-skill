# Install, per harness

The README covers the three routes that need no explanation. This page is the escape hatch: exact
paths, project scope, and the four things that surprise people.

## Paths

| Harness | Target |
|---|---|
| Universal / shared | `~/.agents/skills/security-review` — Claude Code, Cursor, Codex, Copilot, Gemini CLI, OpenCode, Antigravity, Warp |
| Claude Code | `~/.claude/skills/security-review`, or `<repo>/.claude/skills/` |
| Antigravity IDE / app | `~/.gemini/config/skills/security-review` |
| Antigravity CLI | `~/.gemini/antigravity-cli/skills/security-review`, or `<workspace>/.agents/skills/` |
| OpenCode | `~/.config/opencode/skills/security-review`, or `<repo>/.opencode/skills/` |
| Hermes | `~/.hermes/skills/software-development/security-review` |
| Project scope | `<repo>/.agents/skills/security-review` |

`gh skill install --agent <name>` writes the matching row for you; `bash install.sh --agent <name>`
does the same for the six names it knows, `--copy` instead of symlinking where symlinks are awkward.

## Four things that bite

- Antigravity scans **one level deep** — the skill folder must sit directly inside `skills/`.
- A **new** top-level skill directory needs a restart in most tools; Claude Code picks new dirs up
  live.
- Hermes builds its skill index at session start, so the next session sees it.
- `gitleaks`, `osv-scanner` and `semgrep` are optional and detected at runtime. A missing one is
  reported as skipped — never as clean.

## Requirements

`bash` and `python3` for the scripts. Nothing else: no Node, no package install, no network.

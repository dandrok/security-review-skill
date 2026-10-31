#!/usr/bin/env bash
# Install the security-review skill into one or more agent skill directories.
#
# Symlinks by default, so edits in this repo take effect everywhere. Use --copy on
# filesystems where symlinks are awkward (or when an agent refuses to follow them).
#
# Usage:
#   bash install.sh [--agent all|antigravity-cli|antigravity|claude|opencode|agents|hermes|project]
#                   [--copy] [--dry-run]

set -u

SKILL_NAME="security-review"
SRC="$(cd "$(dirname "$0")" && pwd)/skills/$SKILL_NAME"
MODE="symlink"
DRY=0
AGENTS=""
COPY_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    -a|--agent) AGENTS="${2:-}"; shift 2 ;;
    --copy) MODE="copy"; shift ;;
    --symlink) MODE="symlink"; shift ;;
    -n|--dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -f "$SRC/SKILL.md" ] || { echo "error: SKILL.md not found at $SRC" >&2; exit 2; }
[ -n "$AGENTS" ] || AGENTS="all"

dest_for() {
  case "$1" in
    antigravity-cli) echo "$HOME/.gemini/antigravity-cli/skills" ;;
    antigravity)     echo "$HOME/.gemini/config/skills" ;;
    claude)          echo "$HOME/.claude/skills" ;;
    opencode)        echo "$HOME/.config/opencode/skills" ;;
    agents)          echo "$HOME/.agents/skills" ;;
    hermes)          echo "$HOME/.hermes/skills/software-development" ;;
    project)         echo "$PWD/.agents/skills" ;;
    *) echo "" ;;
  esac
}

install_one() {
  local agent="$1" root target
  root="$(dest_for "$agent")"
  if [ -z "$root" ]; then
    echo "  ?  $agent: unknown agent (see --help)"
    return 1
  fi
  target="$root/$SKILL_NAME"

  if [ "$DRY" -eq 1 ]; then
    echo "  -> $agent: $target ($MODE)"
    return 0
  fi

  mkdir -p "$root" || { echo "  !  $agent: cannot create $root"; return 1; }
  if [ -e "$target" ] || [ -L "$target" ]; then
    rm -rf "$target" 2>/dev/null || { echo "  !  $agent: cannot replace $target"; return 1; }
  fi

  if [ "$MODE" = "copy" ]; then
    cp -R "$SRC" "$target"
  else
    ln -s "$SRC" "$target"
  fi

  if [ -f "$target/SKILL.md" ]; then
    echo "  ok $agent: $target"
  else
    echo "  !  $agent: install looks broken at $target"
    return 1
  fi
}

echo "security-review -> agent skill dirs ($MODE)"
echo "source: $SRC"
echo

FAILED=0
if [ "$AGENTS" = "all" ]; then
  for a in antigravity-cli antigravity claude opencode agents hermes; do
    install_one "$a" || FAILED=1
  done
else
  for a in $(echo "$AGENTS" | tr ',' ' '); do
    install_one "$a" || FAILED=1
  done
fi

echo
if [ "$DRY" -eq 1 ]; then
  echo "dry run — nothing changed."
else
  echo "done. start a new agent session (Hermes builds its skill index at session start)."
  echo "verify: ask the agent \"list your skills\" or run /skills in Antigravity CLI."
fi
exit "$FAILED"

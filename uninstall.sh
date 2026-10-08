#!/usr/bin/env bash
# Removes dont-delete-my-drive: the hook file, its hook entry, and the rules install.sh added.
# Your other settings are left alone. settings.json is backed up first.
set -euo pipefail

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
HOOK_FILE="$CLAUDE_DIR/hooks/dont-delete-my-drive.py"
SETTINGS="$CLAUDE_DIR/settings.json"

say() { printf '%s\n' "$*"; }
die() { printf 'dont-delete-my-drive: %s\n' "$*" >&2; exit 1; }

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || die "needs python3 on your PATH"

if [ -f "$SETTINGS" ]; then
  BACKUP="$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
  cp "$SETTINGS" "$BACKUP"
  say "Backed up settings to $BACKUP"
  SETTINGS="$SETTINGS" "$PY" - <<'PY'
import json, os

MARK = "dont-delete-my-drive"
path = os.environ["SETTINGS"]
data = json.load(open(path))

pre = data.get("hooks", {}).get("PreToolUse", [])
for entry in pre:
    entry["hooks"] = [h for h in entry.get("hooks", []) if MARK not in str(h.get("command", ""))]
pre[:] = [e for e in pre if e.get("hooks")]
if not pre and "PreToolUse" in data.get("hooks", {}):
    del data["hooks"]["PreToolUse"]
if "hooks" in data and not data["hooks"]:
    del data["hooks"]

ours_deny = {
    "Bash(sudo *)", "Bash(doas *)", "Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(rm -rf ~/)",
    "Bash(rm -rf $HOME)", "Bash(diskutil erase*)", "Bash(diskutil zeroDisk*)",
    "Bash(diskutil secureErase*)", "Bash(diskutil partitionDisk*)", "Bash(mkfs*)",
    "Bash(newfs*)", "Bash(tmutil delete*)", "Bash(tmutil disable*)", "Bash(gh repo delete*)",
}
ours_ask = {
    "Edit(~/.claude/settings.json)", "Edit(~/.claude/settings.local.json)",
    "Edit(~/.claude/hooks/**)", "Edit(~/.claude/dont-delete-my-drive.json)",
    "Edit(**/.claude/settings.json)", "Edit(**/.claude/settings.local.json)",
}
perms = data.get("permissions", {})
for key, ours in (("deny", ours_deny), ("ask", ours_ask)):
    if key in perms:
        perms[key] = [r for r in perms[key] if r not in ours]
        if not perms[key]:
            del perms[key]

auto = data.get("autoMode", {})
for key in ("hard_deny", "soft_deny"):
    if key in auto:
        auto[key] = [l for l in auto[key] if not (isinstance(l, str) and l.startswith(MARK + ":"))]
        if auto[key] == ["$defaults"] or not auto[key]:
            del auto[key]
if "autoMode" in data and not data["autoMode"]:
    del data["autoMode"]

with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print("Removed our entries from " + path)
PY
fi

if [ -f "$HOOK_FILE" ]; then
  rm "$HOOK_FILE"
  say "Removed $HOOK_FILE"
fi
say "Done. Start a new Claude Code session. Your config file (if any) at $CLAUDE_DIR/dont-delete-my-drive.json was left in place."

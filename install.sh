#!/usr/bin/env bash
# dont-delete-my-drive installer. Safe to run again; it replaces its own entries.
#
#   ./install.sh                 from a clone
#   curl -fsSL https://raw.githubusercontent.com/GitDomHub/dont-delete-my-drive/main/install.sh | bash
#
# Options:
#   --sudo-ask    let Claude ask for sudo instead of being blocked (Linux users who want
#                 `sudo apt install` with a prompt). Pass via: curl ... | bash -s -- --sudo-ask
#
# What it does: copies one Python file to ~/.claude/hooks/, backs up ~/.claude/settings.json,
# then adds the hook plus a few permission rules to it. Nothing else is touched.
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/GitDomHub/dont-delete-my-drive/main"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
HOOK_DIR="$CLAUDE_DIR/hooks"
HOOK_FILE="$HOOK_DIR/dont-delete-my-drive.py"
SETTINGS="$CLAUDE_DIR/settings.json"
CONFIG="$CLAUDE_DIR/dont-delete-my-drive.json"
SUDO_MODE="deny"

for arg in "$@"; do
  case "$arg" in
    --sudo-ask) SUDO_MODE="ask" ;;
    -h|--help) sed -n '2,12p' "$0" 2>/dev/null || true; exit 0 ;;
    *) printf 'dont-delete-my-drive: unknown option %s\n' "$arg" >&2; exit 1 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'dont-delete-my-drive: %s\n' "$*" >&2; exit 1; }

# 1. Find Python 3.6+
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 \
     && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
    PY="$(command -v "$candidate")"
    break
  fi
done
[ -n "$PY" ] || die "needs Python 3.6 or newer on your PATH (python3). Install it and run this again."

# 2. Put the hook file in place
mkdir -p "$HOOK_DIR"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -f "$HERE/dont-delete-my-drive.py" ]; then
  cp "$HERE/dont-delete-my-drive.py" "$HOOK_FILE"
  say "Copied hook to $HOOK_FILE"
else
  curl -fsSL "$REPO_RAW/dont-delete-my-drive.py" -o "$HOOK_FILE" || die "could not download the hook"
  say "Downloaded hook to $HOOK_FILE"
fi
chmod 755 "$HOOK_FILE"

# 3. Back up settings.json
if [ -f "$SETTINGS" ]; then
  "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' "$SETTINGS" 2>/dev/null \
    || die "$SETTINGS is not valid JSON. Fix it first so nothing gets lost."
  BACKUP="$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
  cp "$SETTINGS" "$BACKUP"
  say "Backed up settings to $BACKUP"
fi

# 4. Optional config for sudo mode
if [ "$SUDO_MODE" = "ask" ]; then
  if [ -f "$CONFIG" ]; then
    CONFIG="$CONFIG" "$PY" - <<'PY'
import json, os
p = os.environ["CONFIG"]
try:
    d = json.load(open(p))
except ValueError:
    d = {}
d["sudo"] = "ask"
json.dump(d, open(p, "w"), indent=2)
PY
  else
    printf '{\n  "sudo": "ask"\n}\n' > "$CONFIG"
  fi
  say "sudo will ask instead of being blocked ($CONFIG)"
fi

# 5. Merge the hook and rules into settings.json
HOOK_CMD="\"$PY\" \"$HOOK_FILE\" || { echo 'dont-delete-my-drive could not run, so this command is blocked. Check that python3 works and that $HOOK_FILE exists.' >&2; exit 2; }"

SETTINGS="$SETTINGS" HOOK_CMD="$HOOK_CMD" SUDO_MODE="$SUDO_MODE" "$PY" - <<'PY'
import json, os

MARK = "dont-delete-my-drive"
path = os.environ["SETTINGS"]
sudo_mode = os.environ["SUDO_MODE"]
data = json.load(open(path)) if os.path.exists(path) else {}

# Hook: drop any older copy of ours, then add the current one.
hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])
for entry in pre:
    entry["hooks"] = [h for h in entry.get("hooks", []) if MARK not in str(h.get("command", ""))]
pre[:] = [e for e in pre if e.get("hooks")]
pre.append({
    "matcher": "Bash|mcp__terminal__run_in_terminal",
    "hooks": [{
        "type": "command",
        "command": os.environ["HOOK_CMD"],
        "timeout": 15,
        "statusMessage": "dont-delete-my-drive check",
    }],
})

# Permission rules: belt and braces for the literal worst cases, and prompts
# before anything edits this hook or the settings that load it.
deny = [
    "Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(rm -rf ~/)", "Bash(rm -rf $HOME)",
    "Bash(diskutil erase*)", "Bash(diskutil zeroDisk*)", "Bash(diskutil secureErase*)",
    "Bash(diskutil partitionDisk*)", "Bash(mkfs*)", "Bash(newfs*)",
    "Bash(tmutil delete*)", "Bash(tmutil disable*)", "Bash(gh repo delete*)",
]
if sudo_mode == "deny":
    deny = ["Bash(sudo *)", "Bash(doas *)"] + deny
ask = [
    "Edit(~/.claude/settings.json)", "Edit(~/.claude/settings.local.json)",
    "Edit(~/.claude/hooks/**)", "Edit(~/.claude/dont-delete-my-drive.json)",
    "Edit(**/.claude/settings.json)", "Edit(**/.claude/settings.local.json)",
]
perms = data.setdefault("permissions", {})
for key, rules in (("deny", deny), ("ask", ask)):
    cur = perms.setdefault(key, [])
    if sudo_mode == "ask" and key == "deny":
        cur[:] = [r for r in cur if r not in ("Bash(sudo *)", "Bash(doas *)")]
    for r in rules:
        if r not in cur:
            cur.append(r)

# Auto-mode classifier rules, for what a shell parser can't see.
hard = [
    MARK + ": Deleting, wiping, formatting, erasing or recursively removing a disk, volume, "
    "partition, the root filesystem, /Users or /home, the home folder (~), ~/Documents, "
    "~/Desktop, ~/Downloads, ~/Library, ~/.claude, ~/.ssh, any external drive, or any folder "
    "above the current working directory, by any means (rm, find -delete, rsync --delete, "
    "PowerShell Remove-Item, scripts in Python/Node/Ruby, osascript or anything else).",
    MARK + ": Disabling, editing, renaming or removing the hook at ~/.claude/hooks/"
    "dont-delete-my-drive.py, or removing hooks or permission rules from any "
    ".claude/settings*.json, including setting disableAllHooks.",
    MARK + ": Deleting or disabling backups (Time Machine, snapshots, NAS syncs) or emptying the Trash.",
]
if sudo_mode == "deny":
    hard.append(MARK + ": Running sudo or doas.")
soft = [
    MARK + ": Recursively deleting any folder outside temp folders (/tmp, /var/folders, the "
    "session scratchpad) or regenerable build output (node_modules, dist, build, .next, caches). "
    "Prefer moving it to an archive folder or the Trash.",
    MARK + ": Force-pushing, git reset --hard, git clean -f, deleting an unmerged branch, or "
    "discarding uncommitted changes.",
]
auto = data.setdefault("autoMode", {})
for key, lines in (("hard_deny", hard), ("soft_deny", soft)):
    cur = auto.setdefault(key, [])
    cur[:] = [l for l in cur if not (isinstance(l, str) and l.startswith(MARK + ":"))]
    if not cur:
        cur.append("$defaults")
    cur.extend(lines)

with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print("Updated " + path)
PY

# 6. Self-test
VERDICT="$(printf '%s' '{"tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}' | "$PY" "$HOOK_FILE")"
case "$VERDICT" in
  *'"deny"'*) say "Self-test passed: rm -rf ~ is blocked." ;;
  *) die "self-test failed: the hook did not block rm -rf ~. Output was: $VERDICT" ;;
esac
OK="$(printf '%s' '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | "$PY" "$HOOK_FILE")"
[ -z "$OK" ] || die "self-test failed: the hook flagged a harmless command. Output was: $OK"

say ""
say "Installed. Start a new Claude Code session so it picks up the hook."
say "Settings file: $SETTINGS"
say "Optional config: $CONFIG (see README)"

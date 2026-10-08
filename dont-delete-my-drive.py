#!/usr/bin/env python3
"""dont-delete-my-drive: a PreToolUse hook for Claude Code.

Checks every shell command before it runs and refuses the ones that would
wipe a disk, the home folder, the project, external drives or backups.

  deny: Claude cannot run it. If the step is needed, the user runs it.
  ask:  Claude Code shows its normal permission prompt first.

Install with install.sh (adds this to ~/.claude/settings.json under
hooks.PreToolUse). Optional config: ~/.claude/dont-delete-my-drive.json.
Tests: python3 test_dont_delete_my_drive.py

https://github.com/GitDomHub/dont-delete-my-drive  (MIT)
"""
import json
import os
import re
import shlex
import sys

__version__ = "1.0.0"

HOME = os.path.normpath(os.path.expanduser("~"))
CLAUDE_DIR = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(HOME, ".claude")
CONFIG_PATH = os.path.join(CLAUDE_DIR, "dont-delete-my-drive.json")

ALLOW, ASK, DENY = 0, 1, 2

# Never deleted or moved away by Claude, nor any folder that contains them.
DEFAULT_PROTECTED = [
    os.path.join(HOME, "Library", "Mobile Documents"),   # iCloud Drive
    os.path.join(HOME, "Library", "CloudStorage"),       # Dropbox, Drive, OneDrive
    os.path.join(HOME, "Library", "Keychains"),
    os.path.join(CLAUDE_DIR, "projects"),                # Claude's memory
    os.path.join(CLAUDE_DIR, "skills"),
    os.path.join(CLAUDE_DIR, "hooks"),                   # this file lives here
]
# Protected folders directly inside ~. Any other folder in ~ asks first.
PROTECTED_HOME_CHILDREN = {
    "Documents", "Desktop", "Downloads", "Library", "Pictures", "Movies",
    "Music", "Videos", "Templates", "Applications", "Public", "Developer",
    "Projects", "Dropbox", "Google Drive", "OneDrive", ".ssh", ".gnupg",
    ".aws", ".kube", ".docker", ".config", ".local", ".claude", ".Trash",
}
# Deleting inside these is fine. Deleting the folder itself is not.
DEFAULT_TEMP_ROOTS = ["/tmp", "/private/tmp", "/var/folders", "/private/var/folders",
                      "/var/tmp", "/dev/shm"]
# Build output and caches that tools recreate on the next run.
DEFAULT_REGENERABLE = {
    "node_modules", "dist", "build", "out", ".next", ".nuxt", ".turbo", ".svelte-kit",
    ".astro", ".vite", ".parcel-cache", ".pytest_cache", "__pycache__", ".mypy_cache",
    ".ruff_cache", "coverage", ".wrangler", ".cache", "target", ".gradle", "vendor",
    ".venv", "venv", ".tox", "DerivedData", ".angular", ".expo",
}
MOUNT_ROOT = re.compile(r"^/(Volumes|media|mnt)/")
WSL_WINDOWS = re.compile(r"^/mnt/[a-z]/(Users|Windows|Program Files)(/[^/]+)?$")

# Set from the config file in apply_config().
PROTECTED = list(DEFAULT_PROTECTED)
TEMP_ROOTS = list(DEFAULT_TEMP_ROOTS)
REGENERABLE = set(DEFAULT_REGENERABLE)
SUDO_LEVEL = DENY

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# Commands that run another command; value = their flags that take an argument.
WRAPPERS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-U", "-r", "-t"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-P"},
    "command": set(), "builtin": set(), "exec": {"-a"},
    "nice": {"-n"}, "nohup": set(), "time": set(), "stdbuf": set(),
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "caffeinate": {"-t", "-w"},
    "xargs": {"-I", "-J", "-L", "-n", "-P", "-s", "-E", "-d", "-R", "-S"},
    "npx": {"-p", "--package"}, "bunx": {"-p", "--package"}, "pnpx": set(),
}
SSH_ARG_FLAGS = set("BbcDEeFIiJLlmOoPpQRSWw")
FIND_FILTERS = {
    "-name", "-iname", "-path", "-ipath", "-wholename", "-regex", "-iregex",
    "-type", "-newer", "-mtime", "-mmin", "-size", "-empty", "-user", "-perm",
}
DISKUTIL_WIPE = {
    "erasedisk", "erasevolume", "reformat", "zerodisk", "randomdisk",
    "secureerase", "partitiondisk", "splitpartition", "mergepartitions",
    "eraseoptical", "resizevolume",
}
TMUTIL_WIPE = {
    "delete", "deletelocalsnapshots", "thinlocalsnapshots", "disable",
    "removedestination", "deleteinprogress",
}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SHELL_VAR = re.compile(r"\$\{(\w+)\}|\$(\w+)")
DEVICE = re.compile(r"^(of=)?/dev/(r?disk\d|sd[a-z]|nvme|hd[a-z]|vd[a-z]|mmcblk)")
GLOB_CHARS = set("*?[{")
HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SUBSHELL = re.compile(r"[$<>]\(([^()]*)\)|`([^`]*)`")

# Checked against the raw command text, wherever it appears.
WIN_DELETE = r"\b(rm|rd|rmdir|del|erase|Remove-Item|ri)\b"
WIN_ROOT = (r"(\s|[\"'])([A-Za-z]:\\?|\$env:USERPROFILE\\?|\$env:SystemDrive\\?|\$HOME\\?"
            r"|[A-Za-z]:\\Users\\?|[A-Za-z]:\\Users\\[^\\\s\"']+\\?)[\"']?(\s|$|[;|&])")
RAW_CHECKS = [
    (DENY, re.compile(r"--no-preserve-root"), "rm --no-preserve-root"),
    (DENY, re.compile(r"empty\s+(the\s+)?trash", re.I),
     "emptying the Trash, which deletes for good"),
    (DENY, re.compile(r"\b(Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition|diskpart)\b", re.I),
     "a Windows disk format or partition command"),
    (DENY, re.compile(WIN_DELETE + r"[^\n;|&]*?" + WIN_ROOT, re.I),
     "deleting a drive root or user profile folder"),
    (ASK, re.compile(r"\b(rd|rmdir)\s+(/\w\s+)*/s\b|\bdel\s+(/\w\s+)*/s\b"
                     r"|\bRemove-Item\b[^\n;|&]*-Recurse", re.I),
     "a recursive Windows delete"),
    (ASK, re.compile(r"shutil\.rmtree|os\.removedirs|\brmSync\b|\bfs\.rm(dir)?(Sync)?\s*\("
                     r"|FileUtils\.rm_r|\bremove_dir_all\b|\bos\.RemoveAll\b", re.I),
     "a script that deletes folders"),
    (ASK, re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b", re.I),
     "SQL that drops or empties a table"),
    (ASK, re.compile(r"disableAllHooks"),
     "the setting that switches off every hook, this guard included"),
]
GUARD_FILES = re.compile(r"\.claude/(settings(\.local)?\.json|hooks/|dont-delete-my-drive\.json)")
WRITE_HINT = re.compile(
    r"(?<![0-9&])>(?!&)|\bsed\s+-i|\bperl\s+-\w*i|\b(mv|rm|cp|tee|truncate|ln|chmod|"
    r"chflags|install|rsync|ditto|python3?|node|ruby|osascript|trash)\b")
# Used only when the command can't be parsed (unbalanced quotes and the like).
FALLBACK_CHECKS = [
    (ASK, re.compile(r"(^|[\s;&|(`])(sudo|doas)\s"), "what looks like sudo in a command the guard couldn't parse"),
    (DENY, re.compile(r"diskutil\s+(\S*erase|zerodisk|randomdisk|secureerase|partitiondisk"
                      r"|reformat|apfs\s+(delete|erase))", re.I), "diskutil wiping a disk"),
    (DENY, re.compile(r"\bof=/dev/|>\s*/dev/r?disk|\bmkfs|\bnewfs"), "writing onto a disk device"),
    (DENY, re.compile(r"\brm\s+(-\S+\s+)*-\S*[rR]\S*\s+(-\S+\s+)*[\"']?(/|~|\$\{?HOME\}?)/?\*?[\"']?(\s|$|[;&|])"),
     "rm -r on / or ~"),
    (ASK, re.compile(r"\brm\s+(-\S+\s+)*(-\S*[rR]|--recursive)|\bfind\b.*\s-delete\b"
                     r"|\bgit\s+(reset\s+--hard|clean\s+-\S*f|push\s.*(\s-f\b|--force))"),
     "a delete the guard couldn't fully read"),
]


# ---------------------------------------------------------------- config

def expand(path):
    return os.path.normpath(os.path.expanduser(str(path)))


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def apply_config(cfg):
    """Merge the user's config into the module-level rule tables."""
    global PROTECTED, TEMP_ROOTS, REGENERABLE, SUDO_LEVEL
    strings = lambda key: [v for v in cfg.get(key, []) if isinstance(v, str)]  # noqa: E731
    PROTECTED = list(DEFAULT_PROTECTED) + [expand(p) for p in strings("protected")]
    TEMP_ROOTS = list(DEFAULT_TEMP_ROOTS)
    for p in strings("safe_to_delete_in"):
        p = expand(p)
        if p != "/" and not inside(HOME, p):   # never whitelist ~ or anything above it
            TEMP_ROOTS.append(p)
    REGENERABLE = set(DEFAULT_REGENERABLE) | set(strings("regenerable"))
    SUDO_LEVEL = ASK if cfg.get("sudo") == "ask" else DENY


class Findings:
    def __init__(self, cwd):
        self.cwd = cwd
        self.vars = {}  # VAR=value set earlier in the same command; None = unknown
        self.level = ALLOW
        self.reasons = {ASK: [], DENY: []}

    def add(self, level, reason):
        if level == ALLOW:
            return
        self.level = max(self.level, level)
        if reason not in self.reasons[level]:
            self.reasons[level].append(reason)


# ---------------------------------------------------------------- paths

def short(path):
    return "~" + path[len(HOME):] if inside(path, HOME) else path


def inside(path, folder):
    """True if path is folder itself or somewhere below it."""
    if folder == "/":
        return True
    return path == folder or path.startswith(folder + "/")


def in_temp(path):
    return bool(path) and any(inside(path, t) and path != t for t in TEMP_ROOTS)


def resolve(raw, cwd, known=None):
    """Absolute path for raw, or (None, why) when it can't be known in advance.

    known: variables set to plain values earlier in the same command.
    """
    def substitute(match):
        name = match.group(1) or match.group(2)
        if name == "HOME":
            return HOME
        value = (known or {}).get(name)
        return match.group(0) if value is None else value

    p = SHELL_VAR.sub(substitute, raw)
    if p == "~" or p.startswith("~/"):
        p = HOME + p[1:]
    elif p.startswith("~"):
        return None, "another user's home (%s)" % raw
    if "$" in p or "`" in p:
        return None, ("a path built from a variable (%s); an empty variable can "
                      "turn it into / or ~" % raw)
    if not p.startswith("/"):
        if not cwd:
            return None, "a relative path (%s) after a cd the guard can't follow" % raw
        p = os.path.join(cwd, p)
    return os.path.normpath("/" + p.lstrip("/")), ""


def glob_base(path):
    """Folder a wildcard path lives in, and whether the wildcard filters names."""
    parts = path.split("/")
    for i, part in enumerate(parts):
        if GLOB_CHARS.intersection(part):
            base = "/".join(parts[:i]) or "/"
            whole = part in ("*", ".*", "**", "*.*") or part.startswith("{")
            return base, not whole
    return path, False


def classify(path):
    """Risk of deleting path and everything under it: (level, reason, hard).

    hard=True means a name filter never softens the verdict to ask.
    """
    if path == "/":
        return DENY, "the whole disk (/)", True
    if inside(HOME, path):
        return DENY, "your home folder or a folder above it (%s)" % path, True
    if path in DEFAULT_TEMP_ROOTS:
        return DENY, "the system temp folder %s" % path, True
    if path in TEMP_ROOTS:
        return ASK, "%s itself (deleting inside it is fine, the folder is not)" % short(path), False
    if in_temp(path):
        return ALLOW, "", False
    if path.count("/") <= 2:
        return DENY, "the top-level folder %s" % path, True
    if MOUNT_ROOT.match(path) and path.count("/") <= 3 or WSL_WINDOWS.match(path):
        return DENY, "an external drive or mounted volume (%s)" % path, True
    for folder in PROTECTED:
        if inside(folder, path):
            if folder == path:
                return DENY, short(folder), False
            return DENY, "%s, which holds %s" % (short(path), short(folder)), False
        if inside(path, folder):
            if REGENERABLE.intersection(path[len(folder):].split("/")):
                return ALLOW, "", False
            return DENY, "%s, inside protected %s" % (short(path), short(folder)), False
    parent, name = os.path.split(path)
    if parent == HOME:
        if name in PROTECTED_HOME_CHILDREN:
            return DENY, "~/" + name, False
        return ASK, "~/%s, a folder directly in your home" % name, False
    if inside(path, os.path.join(HOME, ".claude")):
        return ASK, "Claude's own config (%s)" % short(path), False
    if REGENERABLE.intersection(path.split("/")):
        return ALLOW, "", False
    return ASK, "%s (hard to undo; an archive folder or the Trash is safer)" % short(path), False


def worst(path):
    """classify() on the path and on where its symlinks really lead."""
    verdict = classify(path)
    real = os.path.realpath(path)
    if real != path:
        other = classify(real)
        if other[0] > verdict[0]:
            return other
    return verdict


def judge(raw, ctx, filtered=False):
    """Risk of recursively deleting raw: (level, reason)."""
    path, problem = resolve(raw, ctx.cwd, ctx.vars)
    if path is None:
        return ASK, problem
    base, name_filter = glob_base(path)
    level, reason, hard = worst(base)
    if level == DENY and not hard and not name_filter and os.path.isfile(base):
        level, reason = ASK, "the single file %s" % short(base)  # one file, not a tree
    if level < DENY and ctx.cwd and not in_temp(ctx.cwd) and inside(ctx.cwd, base):
        level, reason, hard = DENY, "the folder Claude is working in, or one above it (%s)" % short(base), False
    if level == DENY and (filtered or name_filter) and not hard:
        level = ASK
    return level, reason


def positional(args):
    return [a for a in args if not a.startswith("-")]


# ---------------------------------------------------------------- commands

def check_rm(args, ctx, via, verb="rm", recursive=False):
    targets, opts_done = [], False
    for a in args:
        if not opts_done and a == "--":
            opts_done = True
        elif not opts_done and a.startswith("--"):
            recursive = recursive or a == "--recursive"
        elif not opts_done and a.startswith("-") and len(a) > 1:
            recursive = recursive or "r" in a or "R" in a
        else:
            targets.append(a)
    if "xargs" in via:
        ctx.add(ASK, "%s fed by xargs, so the guard can't see what it deletes" % verb)
        return
    for t in targets:
        if recursive:
            level, reason = judge(t, ctx)
            ctx.add(level, "%s -r on %s" % (verb, reason))
        elif GLOB_CHARS.intersection(t):
            level, reason = judge(t, ctx, filtered=True)
            ctx.add(min(level, ASK), "%s with a wildcard in %s" % (verb, reason))


def check_trash(args, ctx, via):
    for t in positional(args):
        level, reason = judge(t, ctx)
        if level == DENY:
            ctx.add(DENY, "trash on " + reason)


def check_mv(args, ctx, via):
    pos = positional(args)
    if len(pos) < 2:
        return
    for src in pos[:-1]:
        level, reason = judge(src, ctx)
        if level == DENY:
            ctx.add(DENY, "mv moving away " + reason)
    if pos[-1] == "/dev/null":
        ctx.add(ASK, "mv into /dev/null destroys the file")


def check_chmod(args, ctx, via):
    if not any(a.startswith("-") and "R" in a for a in args):
        return
    for t in positional(args)[1:]:
        level, reason = judge(t, ctx)
        if level == DENY:
            ctx.add(DENY, "recursive permission change on " + reason)


def check_find(args, ctx, via):
    deletes = "-delete" in args
    for i, a in enumerate(args[:-1]):
        if a in ("-exec", "-execdir", "-ok", "-okdir") and cmd_name(args[i + 1]) in (
                "rm", "rimraf", "unlink", "srm", "shred"):
            deletes = True
    if not deletes:
        return
    i, starts = 0, []
    while i < len(args) and args[i] in ("-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x", "-f"):
        if args[i] == "-f" and i + 1 < len(args):
            starts.append(args[i + 1])
            i += 1
        i += 1
    while i < len(args) and not args[i].startswith("-") and args[i] not in ("(", ")", "!"):
        starts.append(args[i])
        i += 1
    filtered = any(a in FIND_FILTERS for a in args)
    for start in starts or ["."]:
        level, reason = judge(start, ctx, filtered)
        ctx.add(level, "find -delete on " + reason)


def check_rsync(args, ctx, via):
    flags, pos = [a for a in args if a.startswith("-")], positional(args)
    if any(f.startswith("--del") for f in flags) and pos:
        dest = pos[-1]
        if ":" in dest and not dest.startswith("/"):
            ctx.add(ASK, "rsync --delete into a remote folder (%s)" % dest)
        else:
            level, reason = judge(dest, ctx)
            ctx.add(level, "rsync --delete on " + reason)
    if "--remove-source-files" in flags:
        ctx.add(ASK, "rsync --remove-source-files deletes the originals")


def check_device_writes(args, ctx, via):
    for a in args:
        if DEVICE.match(a):
            ctx.add(DENY, "writing straight onto disk device %s" % a)


def check_diskutil(args, ctx, via):
    pos = [a.lower() for a in positional(args)]
    if not pos:
        return
    group = pos[0] in ("apfs", "cs", "corestorage", "appleraid", "ar")
    if pos[0] in DISKUTIL_WIPE or (group and len(pos) > 1
                                   and re.search(r"delete|erase|resize|remove|destroy", pos[1])):
        ctx.add(DENY, "diskutil %s can wipe a disk or volume" % " ".join(pos[:2]))


def check_tmutil(args, ctx, via):
    pos = [a.lower() for a in positional(args)]
    if pos and pos[0] in TMUTIL_WIPE:
        ctx.add(DENY, "tmutil %s touches Time Machine backups" % pos[0])


def check_partition_tools(name):
    def check(args, ctx, via):
        pos = [a.lower() for a in positional(args)]
        if name in ("fdisk", "pdisk", "sfdisk", "parted", "wipefs"):
            ctx.add(DENY, "%s edits disk partitions" % name)
        elif name == "gpt" and pos and pos[0] in ("destroy", "remove", "create", "add", "migrate", "recover"):
            ctx.add(DENY, "gpt %s edits disk partitions" % pos[0])
        elif name == "asr" and ("restore" in pos or "--erase" in args):
            ctx.add(DENY, "asr restore can overwrite a whole volume")
    return check


def check_git(args, ctx, via):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    flags = [a for a in rest if a.startswith("-")]
    pos = positional(rest)
    short_flags = "".join(f[1:] for f in flags if not f.startswith("--"))

    def has(*names):
        return any(f == n or f.startswith(n + "=") for f in flags for n in names)

    if sub == "clean" and ("f" in short_flags or has("--force")):
        ctx.add(ASK, "git clean -f deletes untracked files for good")
    elif sub == "reset" and has("--hard"):
        ctx.add(ASK, "git reset --hard throws away uncommitted work")
    elif sub == "push" and ("f" in short_flags or "d" in short_flags
                            or has("--force", "--force-with-lease", "--mirror", "--delete", "--prune")
                            or any(p.startswith((":", "+")) for p in pos)):
        ctx.add(ASK, "git push that overwrites or deletes remote history or branches")
    elif sub == "branch" and ("D" in short_flags or ("d" in short_flags and "f" in short_flags)
                              or (has("--delete") and has("--force"))):
        ctx.add(ASK, "git branch -D deletes a branch even if it isn't merged")
    elif sub == "checkout" and ("--" in rest or "." in pos or "f" in short_flags or has("--force")):
        ctx.add(ASK, "git checkout that throws away uncommitted changes")
    elif sub == "restore" and not (has("--staged") or "S" in short_flags) or (
            sub == "restore" and (has("--worktree") or "W" in short_flags)):
        ctx.add(ASK, "git restore throws away uncommitted changes")
    elif sub == "stash" and pos[:1] in (["drop"], ["clear"]):
        ctx.add(ASK, "git stash %s deletes stashed work" % pos[0])
    elif sub in ("filter-branch", "filter-repo"):
        ctx.add(ASK, "git %s rewrites history" % sub)
    elif sub == "reflog" and pos[:1] in (["expire"], ["delete"]):
        ctx.add(ASK, "git reflog %s removes the undo history" % pos[0])
    elif sub == "gc" and has("--prune"):
        ctx.add(ASK, "git gc --prune removes the undo history")
    elif sub == "update-ref" and "d" in short_flags:
        ctx.add(ASK, "git update-ref -d deletes a ref")
    elif sub == "worktree" and pos[:1] == ["remove"] and ("f" in short_flags or has("--force")):
        ctx.add(ASK, "git worktree remove --force throws away changes in that worktree")


def check_gh(args, ctx, via):
    pos = positional(args)
    if pos[:2] == ["repo", "delete"]:
        ctx.add(DENY, "gh repo delete deletes a GitHub repository")
    elif "delete" in pos[:3]:
        ctx.add(ASK, "gh %s deletes something on GitHub" % " ".join(pos[:2]))
    elif pos[:1] == ["api"] and any("DELETE" in a for a in args):
        ctx.add(ASK, "gh api DELETE request")


def check_cloud_delete(name):
    def check(args, ctx, via):
        if "delete" in args or "rm" in args or "destroy" in args:
            ctx.add(ASK, "%s deleting a cloud resource" % name)
    return check


def ask_always(reason):
    def check(args, ctx, via):
        ctx.add(ASK, reason)
    return check


def check_crontab(args, ctx, via):
    if "-r" in args:
        ctx.add(ASK, "crontab -r removes every scheduled job")


def check_security(args, ctx, via):
    pos = positional(args)
    if pos and pos[0].startswith("delete"):
        ctx.add(ASK, "security %s deletes keychain data" % pos[0])


def check_docker(args, ctx, via):
    pos = positional(args)
    if pos[:2] in (["system", "prune"], ["volume", "prune"], ["volume", "rm"]) or (
            pos[:1] == ["rm"] and any(a.startswith("-") and "v" in a for a in args)):
        ctx.add(ASK, "docker %s deletes volumes or data" % " ".join(pos[:2]))


HANDLERS = {
    "rm": check_rm,
    "rimraf": lambda args, ctx, via: check_rm(args, ctx, via, "rimraf", recursive=True),
    "trash": check_trash,
    "mv": check_mv,
    "chmod": check_chmod, "chown": check_chmod, "chflags": check_chmod,
    "find": check_find,
    "rsync": check_rsync,
    "dd": check_device_writes, "tee": check_device_writes, "cp": check_device_writes,
    "diskutil": check_diskutil,
    "tmutil": check_tmutil,
    "fdisk": check_partition_tools("fdisk"), "pdisk": check_partition_tools("pdisk"),
    "sfdisk": check_partition_tools("sfdisk"), "parted": check_partition_tools("parted"),
    "wipefs": check_partition_tools("wipefs"),
    "gpt": check_partition_tools("gpt"), "asr": check_partition_tools("asr"),
    "git": check_git,
    "gh": check_gh,
    "wrangler": check_cloud_delete("wrangler"),
    "aws": check_cloud_delete("aws"), "gcloud": check_cloud_delete("gcloud"),
    "az": check_cloud_delete("az"), "supabase": check_cloud_delete("supabase"),
    "vercel": check_cloud_delete("vercel"), "fly": check_cloud_delete("fly"),
    "terraform": check_cloud_delete("terraform"), "kubectl": check_cloud_delete("kubectl"),
    "docker": check_docker,
    "shred": ask_always("shred destroys files beyond recovery"),
    "srm": ask_always("srm destroys files beyond recovery"),
    "crontab": check_crontab,
    "security": check_security,
}


# ---------------------------------------------------------------- parsing

def cmd_name(tok):
    return os.path.basename(tok.strip("`\\"))


def unwrap(seg):
    """Skip VAR=value and wrappers (sudo, env, xargs ...).

    Returns (name, args, wrappers, leading VAR=value assignments).
    """
    i, via, assigns = 0, set(), []
    while i < len(seg):
        tok = seg[i]
        if ASSIGNMENT.match(tok):
            if not via:
                assigns.append(tok)
            i += 1
            continue
        name = cmd_name(tok)
        if name not in WRAPPERS:
            return name, seg[i + 1:], via, assigns
        via.add(name)
        i += 1
        while i < len(seg) and seg[i].startswith("-"):
            flag = seg[i]
            i += 1
            if flag == "--":
                break
            if flag in WRAPPERS[name] and i < len(seg):
                i += 1
        if name == "timeout" and i < len(seg):
            i += 1  # the duration
    return None, [], via, assigns


def is_operator(tok):
    return bool(tok) and all(c in "();<>|&" for c in tok)


def is_redirect(tok):
    return is_operator(tok) and set(tok) <= set("<>&") and ("<" in tok or ">" in tok)


def tokenize(text):
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


def split_segments(tokens):
    """Split tokens into simple commands; also return redirect targets."""
    segments, cur, redirects, i = [], [], [], 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.isdigit() and i + 1 < len(tokens) and is_redirect(tokens[i + 1]):
            i += 1  # the "2" in 2>/dev/null
            continue
        if is_redirect(tok):
            if i + 1 < len(tokens):
                redirects.append(tokens[i + 1])
            i += 2
            continue
        if is_operator(tok):
            if tok in ("(", ")") and "find" in [cmd_name(t) for t in cur[:3]]:
                cur.append(tok)  # find's own \( \) grouping
            elif cur:
                segments.append(cur)
                cur = []
            i += 1
            continue
        cur.append(tok)
        i += 1
    if cur:
        segments.append(cur)
    return segments, redirects


def strip_heredocs(command):
    """Drop here-document bodies (plain data) unless a shell is reading them."""
    lines, out, i = command.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        match = HEREDOC.search(line)
        if not match:
            continue
        delim = match.group(2)
        body = []
        while i < len(lines) and lines[i].strip() != delim:
            body.append(lines[i])
            i += 1
        i += 1
        if re.search(r"(^|[\s;&|(])(ba|z|da|k)?sh\b[^<]*<<", line):
            out.extend(body)
    return "\n".join(out)


def shell_script(args):
    """The script string in `bash -c '...'`, or None."""
    for i, a in enumerate(args):
        if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a):
            return args[i + 1] if i + 1 < len(args) else ""
        if not a.startswith("-"):
            return None
    return None


def ssh_command(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if len(args[i]) == 2 and args[i][1] in SSH_ARG_FLAGS else 1
    return " ".join(args[i + 1:]) if i < len(args) else ""


def remember(assigns, ctx):
    for a in assigns:
        name, value = a.split("=", 1)
        ctx.vars[name] = None if ("$" in value or "`" in value) else value


def check_segment(seg, ctx, depth):
    name, args, via, assigns = unwrap(seg)
    if via & {"sudo", "doas"}:
        ctx.add(SUDO_LEVEL, "sudo (admin rights); the user runs admin commands themselves")
    if not name:
        remember(assigns, ctx)
        return
    if name in ("export", "declare", "typeset", "local", "readonly"):
        remember([a for a in args if ASSIGNMENT.match(a)], ctx)
    elif name in ("cd", "pushd"):
        target = next((a for a in args if not a.startswith("-")), "~")
        ctx.cwd, _ = resolve(target, ctx.cwd, ctx.vars)
    elif name == "popd":
        ctx.cwd = None
    elif name in SHELLS:
        script = shell_script(args)
        if script:
            scan(script, ctx, depth + 1)
    elif name == "eval":
        scan(" ".join(args), ctx, depth + 1)
    elif name == "ssh":
        remote = ssh_command(args)
        if remote:
            scan(remote, ctx, depth + 1)
    elif name == "osascript":
        for script in re.findall(r'do shell script\s+"((?:[^"\\]|\\.)*)"', " ".join(args)):
            scan(script.replace('\\"', '"'), ctx, depth + 1)
    elif name.startswith(("mkfs", "newfs")):
        ctx.add(DENY, "%s formats a disk" % name)
    elif name in HANDLERS:
        HANDLERS[name](args, ctx, via)


def scan(command, ctx, depth):
    if depth > 4:
        ctx.add(ASK, "a deeply nested shell command")
        return
    saved_cwd = ctx.cwd
    for match in SUBSHELL.finditer(command):
        inner = match.group(1) or match.group(2)
        if inner and inner.strip():
            scan(inner, ctx, depth + 1)
            ctx.cwd = saved_cwd
    text = strip_heredocs(command).replace("\\\n", " ").replace("\n", " ; ")
    try:
        tokens = tokenize(text)
    except ValueError:
        for level, pattern, reason in FALLBACK_CHECKS:
            if pattern.search(text):
                ctx.add(level, reason)
        return
    segments, redirects = split_segments(tokens)
    for target in redirects:
        if DEVICE.match(target):
            ctx.add(DENY, "writing straight onto disk device %s" % target)
    for seg in segments:
        check_segment(seg, ctx, depth)
    if depth:
        ctx.cwd = saved_cwd


def evaluate(command, cwd):
    ctx = Findings(cwd)
    for level, pattern, reason in RAW_CHECKS:
        if pattern.search(command):
            ctx.add(level, reason)
    if GUARD_FILES.search(command) and WRITE_HINT.search(command):
        ctx.add(ASK, "changes Claude's settings or this safety hook")
    scan(command, ctx, 0)
    return ctx


# ---------------------------------------------------------------- hook I/O

def respond(level, reasons):
    listed = "; ".join(reasons)
    if level == DENY:
        message = (
            "dont-delete-my-drive blocked this command: %s. This hook protects the "
            "disk, the home folder, the project and backups. Do not retry, rephrase, "
            "split it up, or script around it. If the step is really needed, stop and "
            "ask the user to run it themselves in a terminal. To clear things out, move "
            "them into an archive folder or the system Trash so it can be undone." % listed)
        decision = "deny"
    else:
        message = "dont-delete-my-drive: %s. Approve only if you meant this." % listed
        decision = "ask"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": message,
    }}))


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        respond(ASK, ["the hook could not read the command"])
        return 0
    tool_input = data.get("tool_input") or {}
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return 0
    cwd = data.get("cwd") or os.getcwd()
    if tool_input.get("cwd"):
        cwd, _ = resolve(tool_input["cwd"], cwd)
    apply_config(load_config())
    ctx = evaluate(command, cwd)
    if ctx.level:
        respond(ctx.level, ctx.reasons[ctx.level])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail safe: ask, never silently allow
        respond(ASK, ["the hook hit an internal error (%s), so it is asking "
                      "instead of allowing" % exc])
        sys.exit(0)

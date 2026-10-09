#!/usr/bin/env python3
"""Regression tests for dont-delete-my-drive.py. Run: python3 test_dont_delete_my_drive.py

Every case runs as if Claude were working in ~/Projects/demo-app.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("guard", os.path.join(HERE, "dont-delete-my-drive.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

NAMES = {guard.ALLOW: "allow", guard.ASK: "ask", guard.DENY: "deny"}
CWD = os.path.join(guard.HOME, "Projects", "demo-app")
SCRATCH = "/private/tmp/scratch"
# A real folder directly in the home directory, created for the run and removed after,
# because a folder that does not exist is a no-op to delete and is allowed.
HOME_TEST = os.path.join(guard.HOME, ".ddmd-test-%d" % os.getpid())

CASES = [
    # --- wipe the disk, home, project, external drives or backups: never
    ("deny", "rm -rf /"),
    ("deny", "rm -rf /*"),
    ("deny", "rm -rf ~"),
    ("deny", "rm -rf ~/"),
    ("deny", 'rm -rf "$HOME"'),
    ("deny", "rm -rf ${HOME}/*"),
    ("deny", "rm -fr ~/Documents"),
    ("deny", "rm -r -f /Users"),
    ("deny", "rm -rf /home"),
    ("deny", "rm --recursive --force ~/Desktop"),
    ("deny", "rm -rf ~/Projects"),
    ("deny", "rm -rf ~/.ssh"),
    ("deny", "rm -rf ."),
    ("deny", "rm -rf .."),
    ("deny", "rm -rf *"),
    ("deny", "cd ~ && rm -rf *"),
    ("deny", "rm -rf /Applications/Foo.app"),
    ("deny", "rm -rf /Volumes/Backup"),
    ("deny", "rm -rf /Volumes/Backup/Photos"),
    ("deny", "rm -rf /media/user/usb"),
    ("deny", "rm -rf /mnt/c/Users/someone"),
    ("deny", "rm -rf /tmp"),
    ("deny", "rm -rf ~/.claude/projects"),
    ("deny", "rm -rf ~/Library/Mobile\\ Documents"),
    ("deny", "rm -rf --no-preserve-root /"),
    ("deny", "\\rm -rf ~"),
    ("deny", "/bin/rm -rf ~/Library"),
    ("deny", "timeout 5 rm -rf ~/.ssh"),
    ("deny", "FOO=1 nice -n 5 rm -rf ~"),
    ("deny", "sudo rm -rf /tmp/x"),
    ("deny", "sudo ls"),
    ("deny", "bash -c 'rm -rf ~/Desktop'"),
    ("deny", 'sh -c "cd / && rm -rf *"'),
    ("deny", "zsh -lc 'rm -rf ~'"),
    ("deny", "eval rm -rf ~"),
    ("deny", "echo hi; rm -rf /Volumes/Backup"),
    ("deny", "cd /tmp\nrm -rf /"),
    ("deny", "# just a note\nrm -rf ~"),
    ("deny", "echo $(rm -rf ~)"),
    ("deny", 'echo "$(rm -rf ~)"'),
    ("deny", "echo `rm -rf ~`"),
    ("deny", "ssh host 'rm -rf ~'"),
    ("deny", "bash <<EOF\nrm -rf ~\nEOF"),
    ("deny", "find ~ -name '*.md' -delete"),
    ("deny", "find / -exec rm -rf {} \\;"),
    ("deny", "find . -delete"),
    ("deny", "npx rimraf ~/Documents"),
    ("deny", "trash ~/Documents"),
    ("deny", "mv ~/Documents /tmp/x"),
    ("deny", "mv . ../elsewhere"),
    ("deny", "rsync -a --delete empty/ ~/Documents/"),
    ("deny", "chmod -R 000 ~"),
    ("deny", "diskutil eraseDisk APFS X disk2"),
    ("deny", "diskutil apfs deleteVolume disk3s1"),
    ("deny", "dd if=/dev/zero of=/dev/disk2 bs=1m"),
    ("deny", "dd if=/dev/zero of=/dev/sda"),
    ("deny", "cat /dev/zero > /dev/rdisk2"),
    ("deny", "newfs_apfs /dev/disk2"),
    ("deny", "mkfs.ext4 /dev/sda1"),
    ("deny", "wipefs -a /dev/nvme0n1"),
    ("deny", "tmutil deletelocalsnapshots /"),
    ("deny", "tmutil disable"),
    ("deny", "osascript -e 'tell application \"Finder\" to empty the trash'"),
    ("deny", "osascript -e 'do shell script \"rm -rf ~/Desktop\"'"),
    ("deny", "gh repo delete someone/repo --yes"),
    ("deny", "echo don't; rm -rf ~"),
    ("deny", 'S=; rm -rf "$S/"'),
    ("deny", "D=~/Documents && rm -rf $D"),
    # --- Windows (pattern-matched)
    ("deny", "Remove-Item -Recurse -Force C:\\"),
    ("deny", "rd /s /q C:\\"),
    ("deny", "Remove-Item -Recurse $env:USERPROFILE"),
    ("deny", 'Remove-Item -Recurse -Force "C:\\Users\\someone"'),
    ("deny", "Format-Volume -DriveLetter D"),
    ("deny", "diskpart /s wipe.txt"),
    # --- destructive but sometimes legit: the user gets a prompt
    ("ask", 'rm -rf "$DIR/"'),
    ("ask", "rm -rf $TMPDIR/*"),
    ("ask", 'S=$(pwd); rm -rf "$S"'),
    ("ask", 'rm -rf "$UNSET/x"'),
    ("ask", 'rm -rf "%s"' % HOME_TEST),                   # a real folder directly in home
    ("ask", 'rm -rf "%s/old-thing"' % HOME_TEST),         # a real folder, not build output
    ("ask", "rm -f ~/Pictures/*.jpg"),
    ("ask", "rm -rf ~/*.log"),
    ("ask", "ls | xargs rm -rf"),
    ("ask", 'rsync -a --delete src/ "%s/"' % HOME_TEST),
    ("ask", "git reset --hard HEAD~1"),
    ("ask", "git clean -fd"),
    ("ask", "git push --force origin main"),
    ("ask", "git push -f"),
    ("ask", "git push origin :feature"),
    ("ask", "git push origin --delete feature"),
    ("ask", "git branch -D feature"),
    ("ask", "git branch -D feature && git push origin --delete feature"),
    ("ask", "for b in a b c; do git push origin --delete $b; done"),
    ("deny", "for d in ~/Documents ~/Desktop; do rm -rf $d; done"),
    ("deny", "cat <<EOF\n`rm -rf ~`\nEOF"),
    ("ask", "python3 -c \"import shutil; shutil.rmtree(os.path.expanduser('~'))\""),
    ("ask", "git checkout -- ."),
    ("ask", "git checkout ."),
    ("ask", "git restore ."),
    ("ask", "git stash drop"),
    ("ask", "python3 -c \"import shutil; shutil.rmtree('/Users/someone/x')\""),
    ("ask", "python3 -c \"import shutil, os; shutil.rmtree(os.path.expanduser('~/x'))\""),
    ("ask", 'wrangler d1 execute db --command "DROP TABLE users"'),
    ("ask", "npx wrangler r2 bucket delete media"),
    ("ask", "aws s3 rm s3://bucket --recursive"),
    ("ask", "docker system prune -af --volumes"),
    ("ask", "gh release delete v1"),
    ("ask", "sed -i '' 's/a/b/' ~/.claude/settings.json"),
    ("ask", "echo '{}' > .claude/settings.local.json"),
    ("ask", "cp hook.py ~/.claude/hooks/"),
    ("ask", "python3 -c \"import json; json.dump({}, open('/Users/x/.claude/settings.json','w'))\""),
    ("ask", "crontab -r"),
    ("ask", "shred secret.txt"),
    ("ask", "Remove-Item -Recurse .\\build"),
    ("ask", "rd /s /q build"),
    # a permission-rule string inside an unparseable command must not read as a real sudo
    ("ask", "echo \"x: $(jq '.deny|index(\"Bash(sudo *)\")' s.json)\"; echo 'unbalanced"),
    # --- normal work: no prompt
    ("allow", "ls -la"),
    ("allow", "rm file.txt"),
    ("allow", 'rm -f "notes/old draft.md"'),
    ("allow", "rm *.md"),
    ("allow", "rm -f zoom*.png"),
    ("allow", "rm -rf *.log"),
    ("allow", "rm -f /tmp/publish-report-*.html"),
    ("allow", "rm -f ~/Movies/Recordings/ENCODED/*.mp4"),
    ("allow", "find . -name '*.bak' -delete"),
    ("allow", "rm -rf ~/scratch"),                       # does not exist: nothing to delete
    ("allow", "rm -rf ~/Projects/old-thing"),            # same
    ("allow", "rsync -a --delete src/ backup/"),         # dest does not exist yet, nothing to delete
    ("allow", "rm -rf node_modules"),
    ("allow", "rm -rf dist build .next"),
    ("allow", "rm -rf node_modules 2>/dev/null"),
    ("allow", "rm -rf packages/web/node_modules"),
    ("allow", "rm -rf ./node_modules/.cache"),
    ("allow", "rm -rf target"),
    ("allow", "rm -rf %s/test" % SCRATCH),
    ("allow", "rm -rf /tmp/foo"),
    ("allow", "cd /tmp/x && rm -rf *"),
    ("allow", 'S=%s; mkdir -p "$S/t/sub" && rm -rf "$S/t"' % SCRATCH),
    ("allow", "export OUT=/tmp/out && rm -rf $OUT/*"),
    ("allow", 'T=$(mktemp -d) && cp x.pdf "$T/" && rm -rf "$T"'),
    ("allow", 'rm -rf "${HOME}/Projects/demo-app/dist"'),
    ("allow", "git status && git add -A && git commit -m 'rm -rf / is scary'"),
    ("allow", 'echo "rm -rf ~"'),
    ("allow", 'grep -rn "rm -rf" .'),
    ("allow", "git push origin main"),
    ("allow", "git push -u origin feature"),
    ("allow", "git branch -d merged"),
    ("allow", "git branch -d feature && git push origin --delete feature"),
    ("allow", "for b in a b c; do git branch -d $b && git push origin --delete $b; done"),
    ("allow", "git push origin --delete x && git branch -d x"),
    ("allow", 'n=$(git log --oneline origin/main..origin/x | wc -l); [ "$n" = 0 ] && git push -q origin --delete x'),
    ("allow", "s=$(gh pr list --state merged --head x --json number -q '.[0].number'); [ -n \"$s\" ] && git push -q origin --delete x"),
    ("allow", "gh pr merge 88 --merge && git push -q origin --delete x"),
    ("allow", "for d in dist build; do rm -rf $d; done"),
    ("allow", 'rm -rf "$repo/worker/.wrangler"'),
    ("allow", "git clone --depth 1 https://example.com/x.git tmp-clone && rm -rf tmp-clone/.git"),
    ("allow", "if [ -d dist ]; then rm -rf dist; fi"),
    ("allow", "cat > README.md <<'EOF'\nNever run `rm -rf ~` or `find . -delete`\nEOF"),
    ("allow", "python3 -c \"import shutil; shutil.rmtree('/Users/someone/proj/build')\""),
    ("allow", "git checkout -- README.md"),
    ("allow", "git restore README.md"),
    ("allow", "git restore --staged file.md"),
    ("allow", "git clean -n"),
    ("allow", "git reset HEAD file.md"),
    ("allow", "git checkout main"),
    ("allow", "diskutil list"),
    ("allow", "tmutil latestbackup"),
    ("allow", "find . -name '*.md'"),
    ("allow", "mv draft.md archive/"),
    ("allow", "mv old-folder archive/"),
    ("allow", "mv ~/Downloads/report.pdf ~/Documents/"),
    ("allow", "trash old.md"),
    ("allow", "cat ~/.claude/settings.json"),
    ("allow", "cat ~/.claude/settings.json | sed 's/=.*/=<set>/'"),
    ("allow", "jq . ~/.claude/settings.json 2>/dev/null"),
    ("allow", "jq '.permissions.deny|index(\"Bash(sudo *)\")' ~/.claude/settings.json"),
    ("allow", "cp -r a b"),
    ("allow", "chmod -R 755 dist"),
    ("allow", "rsync -av src/ /tmp/out/ --delete"),
    ("allow", "python3 script.py"),
    ("allow", "node -e \"require('fs').rmSync('build', {recursive: true})\""),
    ("allow", "python3 - <<'PY'\nimport shutil\nshutil.rmtree('build/tmp', ignore_errors=True)\nPY"),
    ("allow", "npm run build && wrangler deploy"),
    ("allow", "docker ps"),
    ("allow", "cat > notes.md <<'EOF'\nNever run rm -rf ~ and don't panic\nEOF"),
    ("allow", "dd if=in.img of=out.img"),
    ("allow", "del file.txt"),
    ("allow", "Remove-Item file.txt"),
]

# Config: this repo folder as a protected folder, an extra safe folder, sudo set to ask.
CONFIG = {
    "protected": [HERE],
    "safe_to_delete_in": ["~/scratch", "~"],
    "regenerable": [".gradle"],
    "sudo": "ask",
}
DEEP = os.path.join(HERE, ".testtree", "level2", "level3")   # created for the run, removed after
CONFIG_CASES = [
    ("deny", 'rm -rf "%s"' % HERE),
    ("deny", 'rm -rf "%s/assets"' % HERE),                 # top folder of a protected folder
    ("deny", 'rm -rf "%s/.testtree/level2"' % HERE),       # second level too
    ("ask", 'rm -rf "%s"' % DEEP),                         # deeper: normal project rules
    ("allow", 'rm -rf "%s/does-not-exist-xyz"' % HERE),    # nothing there to delete
    ("allow", 'rm -rf "%s/node_modules"' % HERE),          # build output
    ("ask", 'rm -rf "%s/LICENSE"' % HERE),                 # a single file asks, not blocks
    ("deny", 'mv "%s" /tmp/' % HERE),
    ("allow", 'mv "%s/LICENSE" archive/' % HERE),          # moving a file out is archiving
    ("allow", 'mv "%s/assets" "%s/archive/"' % (HERE, HERE)),  # renames inside are fine
    ("allow", 'rm -f "%s/"*.txt' % DEEP),                  # files by pattern, deep enough
    ("ask", 'rm -f "%s/.testtree/"*.png' % HERE),          # files by pattern one level in
    ("allow", 'rm -f "%s/.testtree/level2/zoom"*.png' % HERE),  # files by pattern in a project (level 2)
    ("allow", 'rm -rf "%s/file.txt"' % DEEP),              # one existing file deep inside
    ("ask", "python3 -c \"import shutil; shutil.rmtree('%s')\"" % HERE),  # names the protected root
    ("allow", "python3 -c \"import shutil; shutil.rmtree('%s/x/y/build')\"" % HERE),  # a path inside it
    ("ask", 'rm -f "%s/"*.md' % HERE),                     # files by pattern at the protected root
    ("ask", "python3 -c \"import shutil; shutil.rmtree('%s/x')\"" % HERE),
    ("allow", "rm -rf ~/scratch"),                         # the safe folder itself, but it does not exist
    ("allow", "rm -rf ~/scratch/run-42"),                  # inside it
    ("deny", "rm -rf ~/stuff && rm -rf ~"),                # "~" in safe_to_delete_in is ignored
    ("allow", "rm -rf .gradle"),
    ("ask", "sudo apt install jq"),
    ("deny", "sudo rm -rf /"),
]


def run(cases, label):
    failed = 0
    for expected, command in cases:
        ctx = guard.evaluate(command, CWD)
        got = NAMES[ctx.level]
        if got != expected:
            failed += 1
            reasons = ctx.reasons.get(ctx.level, [])
            print("FAIL want %-5s got %-5s %r  %s" % (expected, got, command, reasons))
    print("%s: %d/%d passed" % (label, len(cases) - failed, len(cases)))
    return failed


def test_git_clean():
    """A folder whose files are all committed is recoverable; untracked files are not."""
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        def git(*a):
            subprocess.run(["git", "-C", tmp, *a], check=True, capture_output=True)
        git("init", "-q")
        git("config", "user.email", "t@example.com")
        git("config", "user.name", "t")
        os.makedirs(os.path.join(tmp, "sub"))
        open(os.path.join(tmp, "sub", "a.txt"), "w").write("a")
        git("add", "-A")
        git("commit", "-q", "-m", "init")
        if not guard.git_clean(os.path.join(tmp, "sub")):
            failed += 1; print("FAIL git_clean: committed folder should be clean")
        open(os.path.join(tmp, "sub", "b.txt"), "w").write("b")
        if guard.git_clean(os.path.join(tmp, "sub")):
            failed += 1; print("FAIL git_clean: untracked file should make it dirty")
    with tempfile.TemporaryDirectory() as tmp:
        if guard.git_clean(tmp):
            failed += 1; print("FAIL git_clean: non-git folder is never clean")
    print("git_clean: %d/3 passed" % (3 - failed))
    return failed


def main():
    os.makedirs(os.path.join(HOME_TEST, "old-thing"), exist_ok=True)
    os.makedirs(DEEP, exist_ok=True)
    open(os.path.join(DEEP, "file.txt"), "w").write("x")
    try:
        guard.apply_config({})
        failed = run(CASES, "defaults")
        guard.apply_config(CONFIG)
        failed += run(CONFIG_CASES, "with config")
    finally:
        guard.apply_config({})
        os.remove(os.path.join(DEEP, "file.txt"))
        for d in (DEEP, os.path.dirname(DEEP), os.path.dirname(os.path.dirname(DEEP))):
            os.rmdir(d)
        os.rmdir(os.path.join(HOME_TEST, "old-thing"))
        os.rmdir(HOME_TEST)
    failed += test_git_clean()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

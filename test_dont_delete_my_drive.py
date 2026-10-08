#!/usr/bin/env python3
"""Regression tests for dont-delete-my-drive.py. Run: python3 test_dont_delete_my_drive.py

Every case runs as if Claude were working in ~/Projects/demo-app.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("guard", os.path.join(HERE, "dont-delete-my-drive.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

NAMES = {guard.ALLOW: "allow", guard.ASK: "ask", guard.DENY: "deny"}
CWD = os.path.join(guard.HOME, "Projects", "demo-app")
SCRATCH = "/private/tmp/scratch"

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
    ("ask", "rm -rf ~/scratch"),
    ("ask", "rm -rf ~/Projects/old-thing"),
    ("ask", "rm -rf ~/.claude/plugins/cache/foo"),
    ("ask", "rm *.md"),
    ("ask", "rm -rf *.log"),
    ("ask", "find . -name '*.bak' -delete"),
    ("ask", "ls | xargs rm -rf"),
    ("ask", "rsync -a --delete src/ backup/"),
    ("ask", "git reset --hard HEAD~1"),
    ("ask", "git clean -fd"),
    ("ask", "git push --force origin main"),
    ("ask", "git push -f"),
    ("ask", "git push origin :feature"),
    ("ask", "git push origin --delete feature"),
    ("ask", "git branch -D feature"),
    ("ask", "git checkout -- ."),
    ("ask", "git restore ."),
    ("ask", "git stash drop"),
    ("ask", "python3 -c \"import shutil; shutil.rmtree('/Users/someone/x')\""),
    ("ask", "node -e \"require('fs').rmSync('x', {recursive: true})\""),
    ("ask", 'wrangler d1 execute db --command "DROP TABLE users"'),
    ("ask", "npx wrangler r2 bucket delete media"),
    ("ask", "aws s3 rm s3://bucket --recursive"),
    ("ask", "docker system prune -af --volumes"),
    ("ask", "gh release delete v1"),
    ("ask", "sed -i '' 's/a/b/' ~/.claude/settings.json"),
    ("ask", "echo '{}' > .claude/settings.local.json"),
    ("ask", "crontab -r"),
    ("ask", "shred secret.txt"),
    ("ask", "Remove-Item -Recurse .\\build"),
    ("ask", "rd /s /q build"),
    # --- normal work: no prompt
    ("allow", "ls -la"),
    ("allow", "rm file.txt"),
    ("allow", 'rm -f "notes/old draft.md"'),
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
    ("allow", 'rm -rf "${HOME}/Projects/demo-app/dist"'),
    ("allow", "git status && git add -A && git commit -m 'rm -rf / is scary'"),
    ("allow", 'echo "rm -rf ~"'),
    ("allow", 'grep -rn "rm -rf" .'),
    ("allow", "git push origin main"),
    ("allow", "git push -u origin feature"),
    ("allow", "git branch -d merged"),
    ("allow", "git restore --staged file.md"),
    ("allow", "git clean -n"),
    ("allow", "git reset HEAD file.md"),
    ("allow", "git checkout main"),
    ("allow", "diskutil list"),
    ("allow", "tmutil latestbackup"),
    ("allow", "find . -name '*.md'"),
    ("allow", "mv draft.md archive/"),
    ("allow", "trash old.md"),
    ("allow", "cat ~/.claude/settings.json"),
    ("allow", "jq . ~/.claude/settings.json 2>/dev/null"),
    ("allow", "cp -r a b"),
    ("allow", "chmod -R 755 dist"),
    ("allow", "rsync -av src/ /tmp/out/ --delete"),
    ("allow", "python3 script.py"),
    ("allow", "npm run build && wrangler deploy"),
    ("allow", "docker ps"),
    ("allow", "cat > notes.md <<'EOF'\nNever run rm -rf ~ and don't panic\nEOF"),
    ("allow", "dd if=in.img of=out.img"),
    ("allow", "del file.txt"),
    ("allow", "Remove-Item file.txt"),
    # a permission-rule string inside an unparseable command must not read as a real sudo
    ("ask", "echo \"x: $(jq '.deny|index(\"Bash(sudo *)\")' s.json)\"; echo 'unbalanced"),
    ("allow", "jq '.permissions.deny|index(\"Bash(sudo *)\")' ~/.claude/settings.json"),
]

# Config: this repo folder as a protected folder, an extra safe folder, sudo set to ask.
CONFIG = {
    "protected": [HERE],
    "safe_to_delete_in": ["~/scratch", "~"],
    "regenerable": [".gradle"],
    "sudo": "ask",
}
CONFIG_CASES = [
    ("deny", 'rm -rf "%s"' % HERE),
    ("deny", 'rm -rf "%s/some-folder"' % HERE),       # anything inside is protected too
    ("allow", 'rm -rf "%s/node_modules"' % HERE),      # except build output
    ("ask", 'rm -rf "%s/LICENSE"' % HERE),             # a single file asks, not blocks
    ("deny", 'mv "%s" /tmp/' % HERE),
    ("allow", 'mv "%s/LICENSE" archive/' % HERE),      # moving a file out is archiving
    ("ask", "rm -rf ~/scratch"),                       # the safe folder itself
    ("allow", "rm -rf ~/scratch/run-42"),              # inside it
    ("deny", "rm -rf ~/stuff && rm -rf ~"),            # "~" in safe_to_delete_in is ignored
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


def main():
    guard.apply_config({})
    failed = run(CASES, "defaults")
    guard.apply_config(CONFIG)
    failed += run(CONFIG_CASES, "with config")
    guard.apply_config({})
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

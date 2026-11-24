#!/bin/sh
# Pushes this project to https://github.com/mobado/scanner.
#
# The first time, GitHub needs to know it is you. This script uses the GitHub CLI (gh),
# which opens your web browser to log in – no password or token is typed here.
#
#   sh scripts/publish-to-github.sh
#
# Later pushes: just run the script again (or "git push").
set -eu
cd "$(dirname "$0")/.."

if ! command -v gh >/dev/null 2>&1; then
    echo "The GitHub CLI (gh) is not installed. Install it with:"
    echo "    sudo apt install gh"
    echo "and run this script again."
    exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
    echo "Logging in to GitHub (a browser window opens) …"
    gh auth login --hostname github.com --git-protocol https --web
fi
gh auth setup-git

# If something was added on github.com (e.g. a README or licence), merge it in first.
git fetch origin
if git rev-parse --verify -q origin/main >/dev/null && ! git merge-base --is-ancestor origin/main HEAD; then
    echo "GitHub has changes that are not here yet – merging them in …"
    if ! git merge --no-edit --allow-unrelated-histories origin/main; then
        git merge --abort || true
        echo "The changes on GitHub conflict with the local ones. Nothing was pushed."
        exit 1
    fi
fi

git push -u origin main
echo "Done: https://github.com/mobado/scanner"

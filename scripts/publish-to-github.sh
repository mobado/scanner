#!/bin/sh
# Pushes this project to https://github.com/mobado/scanner and releases the current version.
#
# The first time, GitHub needs to know it is you. This script uses the GitHub CLI (gh),
# which opens your web browser to log in – no password or token is typed here.
#
#   sh scripts/publish-to-github.sh
#
# Later pushes: just run the script again.
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

version="v$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
if ! git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
    git tag -a "$version" -m "scanner ${version#v}"
fi

if ! git push -u origin main; then
    echo "If GitHub refused to change .github/workflows, run this once and try again:"
    echo "    gh auth refresh -h github.com -s workflow"
    exit 1
fi

# The version tag is sent by name ("git push --follow-tags" silently leaves out tags that
# have no message). GitHub then builds the .deb and puts it on the Releases page.
if git ls-remote --exit-code --tags origin "refs/tags/$version" >/dev/null 2>&1; then
    echo "GitHub already has the tag $version."
else
    git push origin "refs/tags/$version"
fi
echo "Done: https://github.com/mobado/scanner"
echo "The .deb for $version appears on https://github.com/mobado/scanner/releases in about 10 minutes."
echo "Progress: https://github.com/mobado/scanner/actions"

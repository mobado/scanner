#!/bin/sh
# Tries attacks through files (a planted link, an edited whitelist or baseline) against the real
# program, without real root: in a private user namespace the program believes it is root, and
# the "person who used sudo" is another user id.
# Everything happens in a new temporary folder, which is removed afterwards.
#
#   sh scripts/root-write-test.sh target/release/scanner
#
# Needs unprivileged user namespaces and the package uidmap (newuidmap, /etc/subuid).
set -eu
scanner=$(readlink -f "${1:?path of the scanner program}")

if [ "${2:-}" != "--inside" ]; then
    exec unshare --map-root-user --map-auto -- sh "$(readlink -f "$0")" "$scanner" --inside
fi

d=$(mktemp -d)
trap 'rm -rf -- "$d"' EXIT
chmod 755 "$d"
failed=0
check() { # description, command that must succeed
    what=$1
    shift
    if "$@"; then echo "  [OK  ] $what"; else echo "  [FAIL] $what"; failed=1; fi
}
run() { SUDO_UID=1000 SUDO_GID=1000 "$scanner" --no-sudo "$@" >"$d/out" 2>&1; }
scan() { run --cli --modules kernel --no-auto-baseline "$@"; }
untouched() { [ "$(cat "$d/passwd")" = "root:x:0:0" ] && [ "$(stat -c %u "$d/passwd")" = 0 ]; }

# stands for /etc/passwd: root's file, and a home folder of the other user
echo "root:x:0:0" >"$d/passwd"
chmod 644 "$d/passwd"
mkdir "$d/home"
for name in report.json base.json whitelist.toml; do ln -s "$d/passwd" "$d/home/$name.link"; done
chown -R -h 1000:1000 "$d/home"

# the temporary folder is not root's alone here, so root's own files count as changeable too
scan --output "$d/home/report.json" || true
check "a report is written, owned by the person" [ "$(stat -c %u "$d/home/report.json" 2>/dev/null)" = 1000 ]
scan --output "$d/home/report.json.link" || true
check "a report through a planted link is refused" grep -q "not as root" "$d/out"
check "... and the linked file is untouched" untouched
scan --baseline-save "$d/home/base.json.link" || true
check "a baseline through a planted link is refused" grep -q "not as root" "$d/out"
check "... and the linked file is untouched" untouched
run --update-config "$d/home/new/whitelist.toml" || true
check "--update-config in a home folder runs as the person" [ "$(stat -c %u "$d/home/new/whitelist.toml" 2>/dev/null)" = 1000 ]
run --update-config "$d/home/whitelist.toml.link" || true
check "--update-config through a planted link changes nothing" untouched
code=0
scan --config "$d/home/new/whitelist.toml" || code=$?
check "a whitelist the person can change is refused as root" [ "$code" = 3 ]
check "... with the reason" grep -q "The whitelist $d/home/new/whitelist.toml was not used" "$d/out"
scan --baseline-save "$d/home/base.json" || true
check "a baseline saved there belongs to the person" [ "$(stat -c %u "$d/home/base.json" 2>/dev/null)" = 1000 ]
check "... with a note that root will not compare with it" grep -q "will not compare" "$d/out"
for option in --baseline-compare --baseline-diff; do
    code=0
    scan "$option" "$d/home/base.json" || code=$?
    check "$option with a baseline the person can change is refused" [ "$code" = 3 ]
    check "... with the reason" grep -q "The baseline $d/home/base.json was not used" "$d/out"
done
check "the self-test works as root" run --self-test

[ "$failed" = 0 ] && echo "All checks passed." || echo "Some checks FAILED."
exit "$failed"

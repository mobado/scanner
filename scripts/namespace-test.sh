#!/bin/sh
# Tries to fool the scanner with a mount namespace of one's own: bubblewrap puts another program
# (or another library) at an installed one's path, which then looks installed to anyone who reads
# /proc/<pid>/exe or /proc/<pid>/maps. Also checks that honest programs in such a namespace, and a
# running Flatpak app if there is one, raise no alarm. Needs no root. Everything it writes goes in
# a new temporary folder; the processes it starts are ended afterwards.
#
#   sh scripts/namespace-test.sh target/release/scanner
#
# Needs bubblewrap (package bubblewrap) and unprivileged user namespaces.
set -eu
scanner=$(readlink -f "${1:?path of the scanner program}")
for tool in bwrap ssh-agent; do
    command -v "$tool" >/dev/null 2>&1 || { echo "skipped: $tool is not installed"; exit 0; }
done

d=$(mktemp -d)
started=""
cleanup() {
    for pid in $started; do kill "$pid" 2>/dev/null || true; done
    rm -rf -- "$d"
}
trap cleanup EXIT
failed=0
check() { # description, command that must succeed
    what=$1
    shift
    if "$@"; then echo "  [OK  ] $what"; else echo "  [FAIL] $what"; failed=1; fi
}

# a made-up browser profile whose cookies the impostors hold open
mkdir -p "$d/home/.mozilla/firefox/x.default"
echo secret >"$d/home/.mozilla/firefox/x.default/cookies.sqlite"
cookies="$d/home/.mozilla/firefox/x.default/cookies.sqlite"
cp /usr/bin/tail "$d/impostor"

# 1. another program at ssh-agent's path
bwrap --dev-bind / / --bind "$d/impostor" /usr/bin/ssh-agent -- /usr/bin/ssh-agent -f "$cookies" >/dev/null 2>&1 &
started="$started $!"
# 2. the same at a Flatpak browser's path, in a root of its own
bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
    --proc /proc --dev /dev --ro-bind "$d/home" "$d/home" --bind "$d/impostor" /app/extra/chrome \
    -- /app/extra/chrome -f "$cookies" >/dev/null 2>&1 &
started="$started $!"
# 2b. a hidden program in a temporary folder that only its namespace has
bwrap --dev-bind / / --tmpfs /var/tmp --ro-bind "$d/impostor" /var/tmp/.helper -- /var/tmp/.helper -f "$cookies" >/dev/null 2>&1 &
started="$started $!"
# 3. the real ssh, with another file mounted over one of its libraries; ssh stays running while
# the command that should connect it sleeps
waiting_ssh() { # host name to tell it apart; extra bwrap options
    name=$1
    shift
    bwrap --dev-bind / / "$@" -- /usr/bin/ssh -F /dev/null -o BatchMode=yes -o "ProxyCommand=sleep 60" -N "$name.invalid" >/dev/null 2>&1 &
    started="$started $!"
}
library=$(ldd /usr/bin/ssh 2>/dev/null | sed -n 's/.*libcrypto[^ ]* => \([^ ]*\) .*/\1/p')
if [ -n "$library" ]; then
    library=$(readlink -f "$library")
    cp "$library" "$d/library"
    waiting_ssh swapped --bind "$d/library" "$library"
    # 4. the real ssh in a namespace that changes nothing
    waiting_ssh honest
fi
sleep 2
# the process id of the ssh waiting for that host
pid_of() {
    for p in /proc/[0-9]*; do
        case "$(cat "$p/cmdline" 2>/dev/null | tr '\0' ' ')" in
        "/usr/bin/ssh -F /dev/null "*" $1.invalid ") echo "${p#/proc/}" ;;
        esac
    done | head -n 1
}

echo "what the kernel shows as the program file:"
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$(cat "$p/cmdline" 2>/dev/null | tr '\0' ' ')" in
    "/usr/bin/ssh-agent -f $cookies "* | "/app/extra/chrome -f $cookies "*) echo "  PID ${p#/proc/}: $exe" ;;
    esac
done

"$scanner" --cli --no-sudo --no-auto-baseline --modules proc_audit --json --output "$d/report.json" >/dev/null 2>&1 || true
# one finding's text, by rule
find='import json,sys
r=json.load(open(sys.argv[1]))
sys.exit(0 if any(sys.argv[2] in ("-", f["rule"]) and sys.argv[3] in f["title"]+f["evidence"] for f in r["findings"]) else 1)'
has() { # rule, text the same finding must contain
    python3 -I -c "$find" "$d/report.json" "$1" "$2"
}
check "the program posing as ssh-agent is reported" has PROC-FAKE-PROGRAM "/usr/bin/ssh-agent"
check "... and its hold on the cookies, as no rightful reader" has PROC-SECRET-ACCESS "/root/usr/bin/ssh-agent"
check "a program at a Flatpak browser's path may not read cookies" has PROC-SECRET-ACCESS "/root/app/extra/chrome"
check "... and is reported as posing" has PROC-FAKE-PROGRAM "/app/extra/chrome"
check "bubblewrap does not explain away what runs in it" has PROC-NAMESPACE "/root/usr/bin/ssh-agent"
check "a program in a temporary folder of its own namespace is still seen there" has PROC-TMP-EXE "/var/tmp/.helper"
if [ -n "$library" ]; then
    swapped=$(pid_of swapped)
    honest=$(pid_of honest)
    check "a library swapped in under the real ssh is seen" has PROC-KEY-LIBRARY "PID $swapped "
    check "... and named" has PROC-KEY-LIBRARY "$library"
    check "the real ssh in a namespace that changes nothing raises no alarm" sh -c '! "$@"' - python3 -I -c "$find" "$d/report.json" - "PID $honest "
fi
# programs of this computer's own that run in namespaces (Flatpak apps and the like) must not be
# taken for posing ones; anything listed here deserves a look
others=$(python3 -I -c 'import json,sys
r=json.load(open(sys.argv[1]))
for f in r["findings"]:
    if f["rule"]=="PROC-FAKE-PROGRAM" and not f["title"].endswith(("/usr/bin/ssh-agent","/app/extra/chrome")):
        print("    "+f["severity"]+": "+f["title"])' "$d/report.json")
flatpaks=0
for p in /proc/[0-9]*; do
    case "$(readlink "$p/exe" 2>/dev/null)" in /app/*) flatpaks=$((flatpaks + 1)) ;; esac
done
if [ -n "$others" ]; then
    echo "  other programs on this computer reported as posing:"
    echo "$others"
else
    echo "  nothing else is reported as posing ($flatpaks running process(es) show a Flatpak's /app/ path)"
fi

[ "$failed" = 0 ] && echo "All checks passed." || echo "Some checks FAILED."
exit "$failed"

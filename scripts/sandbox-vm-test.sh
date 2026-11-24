#!/bin/sh
# Verifies the scanner in an ISOLATED test environment (disposable VM or container with Debian 13).
#
# The script creates a few HARMLESS test artefacts, runs the scanner and checks that the
# rules fire – and then cleans everything up again. NEVER run it on a production
# machine: it temporarily puts files in /etc and /tmp.
#
# Usage (as root in the test VM):
#   SCANNER=/usr/local/sbin/scanner sh scripts/sandbox-vm-test.sh --i-am-in-a-test-machine
#
# For a test with no system changes at all, run "scanner --self-test" instead
# (it builds everything in a temporary directory).

set -eu

SCANNER="${SCANNER:-scanner}"
WORK="$(mktemp -d /var/tmp/scanner-vmtest.XXXXXX)"
PASS=0
FAIL=0

if [ "${1:-}" != "--i-am-in-a-test-machine" ]; then
    echo "Stopping: this script temporarily changes /etc and /tmp."
    echo "Run it in a disposable VM/container with the flag --i-am-in-a-test-machine."
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (in the test VM)."
    exit 2
fi
if command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt || true)" = "none" ]; then
    echo "Warning: systemd-detect-virt says this is not a VM/container."
    echo "Set SCANNER_ALLOW_PHYSICAL=1 if you really want to continue."
    [ "${SCANNER_ALLOW_PHYSICAL:-0}" = "1" ] || exit 2
fi
if ! grep -q '^13' /etc/debian_version 2>/dev/null && ! grep -qi trixie /etc/os-release; then
    echo "Warning: this does not look like Debian 13 – continuing anyway."
fi

SLEEP_PID=""
HTTP_PID=""
cleanup() {
    [ -n "$SLEEP_PID" ] && kill "$SLEEP_PID" 2>/dev/null || true
    [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null || true
    rm -f /etc/systemd/system/scanner-test-dummy.service \
          /etc/cron.d/scanner-test \
          /tmp/scanner-test.sh /tmp/scanner-test-sleep /tmp/scanner-test-suid
    rm -rf "$WORK"
    systemctl daemon-reload 2>/dev/null || true
    echo "The test artefacts have been removed."
}
trap cleanup EXIT INT TERM

echo "» 1/4 Saving a baseline before the test …"
"$SCANNER" --cli --no-sudo --baseline-save "$WORK/baseline.json" --json --output "$WORK/before.json" >/dev/null 2>&1 || true

echo "» 2/4 Creating harmless test artefacts …"
# a) systemd service pointing to a script in /tmp (NOT enabled or started)
printf '#!/bin/sh\necho harmless test\n' > /tmp/scanner-test.sh
chmod 755 /tmp/scanner-test.sh
cat > /etc/systemd/system/scanner-test-dummy.service <<'EOF'
[Unit]
Description=Harmless test service for scanner (removed automatically)
[Service]
Type=oneshot
ExecStart=/tmp/scanner-test.sh
EOF
# b) cron file that would run the script in /tmp at boot
echo "@reboot root /tmp/scanner-test.sh" > /etc/cron.d/scanner-test
# c) executable in /tmp that runs (a copy of sleep), then removed while it runs
cp /bin/sleep /tmp/scanner-test-sleep
/tmp/scanner-test-sleep 300 &
SLEEP_PID=$!
sleep 1
rm -f /tmp/scanner-test-sleep
# d) SUID bit on a copy of /bin/true in /tmp
cp /bin/true /tmp/scanner-test-suid
chmod 4755 /tmp/scanner-test-suid
# e) a script interpreter listening on a port (loopback only)
if command -v python3 >/dev/null 2>&1; then
    python3 -m http.server 31337 --bind 127.0.0.1 >/dev/null 2>&1 &
    HTTP_PID=$!
    sleep 1
fi

echo "» 3/4 Running the scanner …"
set +e
"$SCANNER" --cli --no-sudo --baseline-compare "$WORK/baseline.json" --json --output "$WORK/after.json"
CODE=$?
set -e
echo "   exit code: $CODE (2 = critical findings, expected)"

echo "» 4/4 Checking that the rules fired …"
check() {
    if grep -q "\"rule\": \"$1\"" "$WORK/after.json"; then
        echo "   [OK  ] $1 – $2"; PASS=$((PASS + 1))
    else
        echo "   [FAIL] $1 – $2"; FAIL=$((FAIL + 1))
    fi
}
check PERS-SYSTEMD-EXEC  "systemd service with ExecStart in /tmp"
check PERS-CRON-CMD      "cron job that runs from /tmp"
check PROC-TMP-EXE       "process running from /tmp"
check PROC-DELETED       "process whose binary is deleted"
check FS-SUID-TEMP       "SUID file in /tmp"
check BASE-SUID-NEW      "new SUID file compared with the baseline"
check BASE-PERSIST-NEW   "new persistence file compared with the baseline"
[ -n "$HTTP_PID" ] && check NET-BINDSHELL "script interpreter listening on port 31337"

echo
echo "Result: $PASS OK, $FAIL failed. Full report: copy $WORK/after.json before the script ends if you want to keep it."
[ "$FAIL" -eq 0 ]

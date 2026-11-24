#!/bin/sh
# Builds a Debian package (.deb) of scanner with Debian's own tool dpkg-deb.
#
#   sh scripts/build-deb.sh
#
# Result: dist/scanner_<version>-1_<arch>.deb
# Install it on any Debian 13 machine with:
#   sudo apt install ./scanner_<version>-1_<arch>.deb
#
# The package contains:
#   /usr/bin/scanner                                   the program (window + CLI)
#   /usr/share/applications/scanner.desktop            menu entry
#   /usr/share/icons/hicolor/scalable/apps/scanner.svg icon
#   /etc/scanner/whitelist.toml                        whitelist (kept on upgrade)
#   /usr/lib/systemd/system/scanner-diff.{service,timer} nightly check (not enabled)
#   /usr/share/doc/scanner/                            README, copyright, changelog, VM test script
set -eu
cd "$(dirname "$0")/.."

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
ARCH="$(dpkg --print-architecture)"
DEB_VERSION="${VERSION}-1"
NAME="scanner_${DEB_VERSION}_${ARCH}"

echo "» Building scanner $VERSION (release) …"
cargo build --release --locked

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/$NAME"

echo "» Putting the files in place …"
install -D -m 0755 target/release/scanner                     "$PKG/usr/bin/scanner"
install -D -m 0644 packaging/deb/scanner.desktop              "$PKG/usr/share/applications/scanner.desktop"
install -D -m 0644 packaging/deb/scanner.svg                  "$PKG/usr/share/icons/hicolor/scalable/apps/scanner.svg"
install -D -m 0644 packaging/whitelist.toml                   "$PKG/etc/scanner/whitelist.toml"
install -d -m 0755 "$PKG/usr/lib/systemd/system"
sed 's|/usr/local/sbin/scanner|/usr/bin/scanner|' packaging/scanner-diff.service > "$PKG/usr/lib/systemd/system/scanner-diff.service"
chmod 0644 "$PKG/usr/lib/systemd/system/scanner-diff.service"
install -m 0644 packaging/scanner-diff.timer                  "$PKG/usr/lib/systemd/system/scanner-diff.timer"
install -D -m 0644 README.md                                  "$PKG/usr/share/doc/scanner/README.md"
install -D -m 0644 packaging/deb/copyright                    "$PKG/usr/share/doc/scanner/copyright"
install -D -m 0755 scripts/sandbox-vm-test.sh                 "$PKG/usr/share/doc/scanner/examples/sandbox-vm-test.sh"
{
    echo "scanner ($DEB_VERSION) unstable; urgency=medium"
    echo
    echo "  * Release $VERSION. See https://github.com/mobado/scanner for details."
    echo
    echo " -- mobado <mobado@users.noreply.github.com>  $(date -R)"
} | gzip -9n > "$PKG/usr/share/doc/scanner/changelog.Debian.gz"
chmod 0644 "$PKG/usr/share/doc/scanner/changelog.Debian.gz"

echo "» Working out the library dependencies …"
DEPENDS="libc6 (>= 2.36), libgcc-s1 (>= 4.2)"
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    mkdir -p "$STAGE/src/debian"
    printf 'Source: scanner\n\nPackage: scanner\nArchitecture: any\n' > "$STAGE/src/debian/control"
    FOUND="$(cd "$STAGE/src" && dpkg-shlibdeps -O "$PKG/usr/bin/scanner" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
    [ -n "$FOUND" ] && DEPENDS="$FOUND"
fi

mkdir -p "$PKG/DEBIAN"
SIZE="$(du -sk --exclude=DEBIAN "$PKG" | cut -f1)"
cat > "$PKG/DEBIAN/control" <<EOF
Package: scanner
Version: $DEB_VERSION
Architecture: $ARCH
Maintainer: mobado <mobado@users.noreply.github.com>
Installed-Size: $SIZE
Depends: $DEPENDS
Recommends: sudo, debsums, libgl1, libegl1, libxkbcommon0, libwayland-client0, libwayland-egl1, libx11-6, libx11-xcb1, libxcursor1, libxi6, libxrandr2
Suggests: chkrootkit, rkhunter, lynis
Section: admin
Priority: optional
Homepage: https://github.com/mobado/scanner
Description: read-only intrusion and backdoor scanner for Debian 13
 Looks for signs of intrusion, backdoors and persistence on Debian 13 "Trixie":
 reverse and bind shells, hidden or disguised processes, programs running from
 /tmp or deleted from disk, new SUID/SGID files, suspicious systemd units, cron
 jobs, SSH keys, sshd and PAM settings. It can also run debsums, chkrootkit,
 rkhunter and lynis. Strictly read-only: it never changes the system.
 .
 Comes with a window and a command line (JSON and text reports, baselines) and
 a nightly systemd timer that compares the system against a saved baseline.
EOF
echo "/etc/scanner/whitelist.toml" > "$PKG/DEBIAN/conffiles"
install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$PKG/DEBIAN/"

mkdir -p dist
dpkg-deb --root-owner-group -Zxz --build "$PKG" "dist/$NAME.deb" >/dev/null
echo "» Done: dist/$NAME.deb"
echo "  Install: sudo apt install ./dist/$NAME.deb"

#!/bin/sh
# Builds a standalone, statically linked CLI binary (without the window) for Debian 13.
# Result: target/static/x86_64-unknown-linux-gnu/release/scanner
#
# The window version cannot be linked statically (it loads graphics libraries
# dynamically), so the static binary is built with --no-default-features.
#
# Alternative with musl (needs: rustup target add x86_64-unknown-linux-musl):
#   cargo build --release --no-default-features --target x86_64-unknown-linux-musl
set -eu
cd "$(dirname "$0")/.."
RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --no-default-features \
    --target x86_64-unknown-linux-gnu --target-dir target/static
BIN=target/static/x86_64-unknown-linux-gnu/release/scanner
file "$BIN" 2>/dev/null || true
echo "Done: $BIN"
echo "Install: sudo install -m 0755 $BIN /usr/local/sbin/scanner"

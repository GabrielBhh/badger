#!/bin/sh
# badger installer — downloads a release tarball, verifies its checksum, and
# installs the binary.
#
# Usage:
#   install.sh [--version vX.Y.Z] [--user]
#
#   --version vX.Y.Z  install a specific release (default: latest)
#   --user            install to ~/.local/bin instead of /usr/local/bin
set -eu

REPO="GabrielBhh/badger"
VERSION=""
USER_INSTALL=0

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}

err() {
    printf 'install.sh: %s\n' "$1" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || err "--version needs an argument (e.g. v0.9.0)"
            VERSION="$2"
            shift 2
            ;;
        --user)
            USER_INSTALL=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "unknown option: $1 (try --help)"
            ;;
    esac
done

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v sha256sum >/dev/null 2>&1 || err "sha256sum is required"

arch=$(uname -m)
case "$arch" in
    x86_64|aarch64) ;;
    *) err "unsupported architecture: $arch (only x86_64 and aarch64 builds are published)" ;;
esac
target="$arch-unknown-linux-musl"

if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d '"' -f 4) || true
    [ -n "$VERSION" ] || err "could not determine the latest release (is one published yet?)"
fi

case "$VERSION" in
    v*) ;;
    *) err "version must look like v0.9.0 (got: $VERSION)" ;;
esac
pkgver=${VERSION#v}

tarball="badger-$pkgver-$target.tar.gz"
base_url="https://github.com/$REPO/releases/download/$VERSION"

tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT INT TERM

printf 'Downloading %s (%s)...\n' "$tarball" "$VERSION" >&2
curl -fL --progress-bar -o "$tmpdir/$tarball" "$base_url/$tarball" \
    || err "download failed: $base_url/$tarball"
curl -fsSL -o "$tmpdir/$tarball.sha256" "$base_url/$tarball.sha256" \
    || err "checksum download failed: $base_url/$tarball.sha256"

printf 'Verifying checksum...\n' >&2
(cd "$tmpdir" && sha256sum -c "$tarball.sha256" >/dev/null) \
    || err "checksum verification FAILED — aborting, nothing installed"

tar -xzf "$tmpdir/$tarball" -C "$tmpdir"
binary="$tmpdir/badger-$pkgver-$target/badger"
[ -f "$binary" ] || err "tarball did not contain the expected badger binary"

if [ "$USER_INSTALL" -eq 1 ]; then
    dest="$HOME/.local/bin"
    mkdir -p "$dest"
    install -m 755 "$binary" "$dest/badger"
else
    dest="/usr/local/bin"
    if [ "$(id -u)" -eq 0 ]; then
        install -m 755 "$binary" "$dest/badger"
    else
        printf 'Installing to %s needs sudo.\n' "$dest" >&2
        sudo install -m 755 "$binary" "$dest/badger"
    fi
fi

printf 'Installed badger %s to %s/badger\n' "$VERSION" "$dest" >&2

if [ "$USER_INSTALL" -eq 1 ]; then
    case ":$PATH:" in
        *":$dest:"*) ;;
        *)
            printf '\nNote: %s is not on your PATH. Add this to your shell profile:\n' "$dest" >&2
            printf '  export PATH="$HOME/.local/bin:$PATH"\n' >&2
            ;;
    esac
fi

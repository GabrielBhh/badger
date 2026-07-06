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

usage() {
    cat <<'EOF'
Usage: install.sh [--version vX.Y.Z] [--user]

  --version vX.Y.Z  install a specific release (default: latest)
  --user            install to ~/.local/bin instead of /usr/local/bin
EOF
}

err() {
    printf 'install.sh: %s\n' "$1" >&2
    exit 1
}

# version_ok checks that $1 matches vX.Y.Z (digits only in each component).
# Rejects anything else, including path-traversal-style strings, since
# $VERSION is later substituted straight into a download URL.
version_ok() {
    case "$1" in
        v[0-9]*.[0-9]*.[0-9]*) ;;
        *) return 1 ;;
    esac
    case "${1#v}" in
        *[!0-9.]*) return 1 ;;
    esac
    save_ifs=$IFS
    IFS=.
    set -- ${1#v}
    IFS=$save_ifs
    [ $# -eq 3 ] || return 1
    for part in "$1" "$2" "$3"; do
        case "$part" in
            ''|*[!0-9]*) return 1 ;;
        esac
    done
}

main() {
    VERSION=""
    USER_INSTALL=0

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

    version_ok "$VERSION" || err "version must look like vX.Y.Z (got: $VERSION)"
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
        [ -n "${HOME:-}" ] || err "--user needs HOME set (nowhere to install to)"
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
}

main "$@"

#!/bin/sh
set -eu

repo="${SSHELPER_REPO:-pietrosig/sshelper}"
asset="${SSHELPER_ASSET:-sshelper}"
url="${SSHELPER_INSTALL_URL:-https://github.com/$repo/releases/latest/download/$asset}"

if [ "${BIN_DIR:-}" ]; then
    bin_dir="$BIN_DIR"
elif [ "${PREFIX:-}" ]; then
    bin_dir="$PREFIX/bin"
else
    bin_dir="$HOME/.local/bin"
fi
target="$bin_dir/sshelper"

download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
        return
    fi
    echo "sshelper install: curl or wget is required" >&2
    exit 127
}

python_ok=false
for py in "${SSHELPER_PYTHON:-}" python3.14 python3.13 python3.12 python3.11 python3; do
    [ -n "$py" ] || continue
    if "$py" -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >/dev/null 2>&1; then
        python_ok=true
        break
    fi
done

if [ "$python_ok" != true ]; then
    echo "sshelper install: Python 3.11+ is required" >&2
    exit 127
fi

tmp="${TMPDIR:-/tmp}/sshelper-install.$$"
trap 'rm -f "$tmp"' EXIT INT HUP TERM

download "$url" "$tmp"
chmod +x "$tmp"

if ! "$py" "$tmp" --version >/dev/null 2>&1; then
    echo "sshelper install: downloaded file did not pass validation" >&2
    exit 1
fi

mkdir -p "$bin_dir"
mv "$tmp" "$target"
chmod +x "$target"
trap - EXIT INT HUP TERM

echo "installed sshelper to $target"
echo "next: run \`sshelper setup\` once"
case ":$PATH:" in
    *:"$bin_dir":*) ;;
    *)
        echo "warning: $bin_dir is not on PATH" >&2
        echo "add this to your shell profile:" >&2
        echo "  export PATH=\"$bin_dir:\$PATH\"" >&2
        ;;
esac

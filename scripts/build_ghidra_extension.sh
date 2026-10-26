#!/usr/bin/env bash
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to a Ghidra 12.2 installation}"
: "${JAVA_HOME:?Set JAVA_HOME to a Java 25 installation}"

if (($# == 0)); then
    case "$(uname -s)" in
        Linux) set -- linux64 ;;
        Darwin) set -- osx ;;
        MINGW*|MSYS*|CYGWIN*) set -- win64 ;;
        *) echo "Unsupported host; pass linux64, win64, or osx explicitly" >&2; exit 2 ;;
    esac
fi

case "$GHIDRA_INSTALL_DIR" in
    *ghidra_12.2_PUBLIC*) ;;
    *) echo "Warning: extension is currently tested against Ghidra 12.2" >&2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
mkdir -p dist

for platform in "$@"; do
    case "$platform" in
        linux64|win64|osx) ;;
        *) echo "Unknown RocksDB platform: $platform" >&2; exit 2 ;;
    esac

    rm -rf build lib
    ./gradlew buildExtension --no-daemon -ProcksdbPlatform="$platform"

    built="$(find dist -maxdepth 1 -type f -name 'ghidra_12.2_PUBLIC_*_mtk-mddb-tools.zip' -printf '%p\n' | sort | tail -1)"
    if [[ -z "$built" ]]; then
        echo "Ghidra extension zip was not produced" >&2
        exit 1
    fi
    out="dist/mtk-mddb-tools-ghidra-12.2-${platform}.zip"
    mv -f "$built" "$out"
    printf 'built %s (%s bytes)\n' "$out" "$(stat -c %s "$out" 2>/dev/null || stat -f %z "$out")"
done

#!/usr/bin/env bash
# rop_scanner — Linux build script
#
# Usage:
#   ./linux_build.sh                    # Release build in ./build
#   BUILD_DIR=out ./linux_build.sh      # custom build dir
#   BUILD_TYPE=Debug ./linux_build.sh   # custom build type
#
# Requires:
#   - C++17 compiler (g++ >= 7 or clang++ >= 5)
#   - CMake >= 3.16
#   - make or ninja

set -euo pipefail

cd "$(dirname "$0")"

# ---- preflight ----------------------------------------------------------
need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[-] '$1' not found."
        echo
        echo "    Install on Debian/Ubuntu : sudo apt install -y cmake g++ make"
        echo "    Install on Fedora/RHEL   : sudo dnf install -y cmake gcc-c++ make"
        echo "    Install on Arch          : sudo pacman -S cmake gcc make"
        exit 1
    fi
}
need cmake

if ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
    echo "[-] No C++ compiler found (g++ or clang++)."
    exit 1
fi

BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
JOBS="$(nproc 2>/dev/null || echo 4)"

echo "[+] cmake:    $(cmake --version | head -1)"
if command -v g++ >/dev/null 2>&1; then
    echo "[+] compiler: $(g++ --version | head -1)"
else
    echo "[+] compiler: $(clang++ --version | head -1)"
fi
echo "[+] kernel:   $(uname -srm)"
echo "[+] target:   ${BUILD_DIR} (${BUILD_TYPE}, ${JOBS} parallel jobs)"
echo

# ---- configure ----------------------------------------------------------
echo "[+] Configuring"
cmake -S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

# ---- build --------------------------------------------------------------
echo
echo "[+] Building"
cmake --build "${BUILD_DIR}" -j "${JOBS}"

# ---- verify -------------------------------------------------------------
BIN="${BUILD_DIR}/bin/rop_scanner"
if [ ! -x "${BIN}" ]; then
    echo
    echo "[-] Build finished but binary not at ${BIN}"
    exit 2
fi

echo
echo "[+] OK → ${BIN}"
"${BIN}" --help | sed -n '1,3p'

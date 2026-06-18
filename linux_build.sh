#!/usr/bin/env bash
# rop_scanner — Linux build script
#
# Usage:
#   ./linux_build.sh                    # Release build in ./build
#   BUILD_DIR=out ./linux_build.sh      # custom build dir
#   BUILD_TYPE=Debug ./linux_build.sh   # custom build type
#   GUI=1 ./linux_build.sh              # build the Qt GUI front-end too
#
# Requires:
#   - C++17 compiler (g++ >= 7 or clang++ >= 5)
#   - CMake >= 3.16
#   - make or ninja
#   - For GUI=1 on Debian/Ubuntu:
#       sudo apt install qt6-base-dev libvulkan-dev
#     on Fedora/RHEL:
#       sudo dnf install qt6-qtbase-devel vulkan-headers

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
GUI="${GUI:-0}"
JOBS="$(nproc 2>/dev/null || echo 4)"

CMAKE_OPTS=("-DCMAKE_BUILD_TYPE=${BUILD_TYPE}")
[ "${GUI}" = "1" ] && CMAKE_OPTS+=("-DBUILD_GUI=ON")

echo "[+] cmake:    $(cmake --version | head -1)"
if command -v g++ >/dev/null 2>&1; then
    echo "[+] compiler: $(g++ --version | head -1)"
else
    echo "[+] compiler: $(clang++ --version | head -1)"
fi
echo "[+] kernel:   $(uname -srm)"
echo "[+] target:   ${BUILD_DIR} (${BUILD_TYPE}, ${JOBS} parallel jobs)$([ "${GUI}" = "1" ] && echo "  +GUI")"
echo

# ---- configure ----------------------------------------------------------
echo "[+] Configuring"
cmake -S . -B "${BUILD_DIR}" "${CMAKE_OPTS[@]}"

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

if [ "${GUI}" = "1" ]; then
    GUI_BIN="${BUILD_DIR}/bin/rop_scanner_gui"
    if [ -x "${GUI_BIN}" ]; then
        echo "[+] GUI → ${GUI_BIN}"
    fi
fi

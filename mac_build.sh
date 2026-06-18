#!/usr/bin/env bash
# rop_scanner — macOS build script
#
# Usage:
#   ./mac_build.sh                    # Release build in ./build
#   BUILD_DIR=out ./mac_build.sh      # custom build dir
#   BUILD_TYPE=Debug ./mac_build.sh   # custom build type
#   GUI=1 ./mac_build.sh              # build the Qt GUI front-end too
#
# Requires:
#   - Xcode Command Line Tools  (xcode-select --install)
#   - CMake >= 3.16             (brew install cmake)
#   - For GUI=1: Qt6            (brew install qt)

set -euo pipefail

cd "$(dirname "$0")"

# ---- preflight ----------------------------------------------------------
if ! command -v cmake >/dev/null 2>&1; then
    echo "[-] cmake not found."
    echo "    Install: brew install cmake     (or https://cmake.org)"
    exit 1
fi

if ! xcode-select -p >/dev/null 2>&1; then
    echo "[-] Xcode Command Line Tools not installed."
    echo "    Install: xcode-select --install"
    exit 1
fi

BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
GUI="${GUI:-0}"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

CMAKE_OPTS=("-DCMAKE_BUILD_TYPE=${BUILD_TYPE}")
if [ "${GUI}" = "1" ]; then
    CMAKE_OPTS+=("-DBUILD_GUI=ON")
    # If Qt6 was installed via Homebrew, help CMake find it.
    for QT_PREFIX in /opt/homebrew/opt/qt /usr/local/opt/qt \
                     "$(brew --prefix qt 2>/dev/null || true)"; do
        if [ -d "${QT_PREFIX}" ]; then
            CMAKE_OPTS+=("-DCMAKE_PREFIX_PATH=${QT_PREFIX}")
            echo "[+] Qt prefix: ${QT_PREFIX}"
            break
        fi
    done
fi

echo "[+] cmake:    $(cmake --version | head -1)"
echo "[+] compiler: $(clang++ --version | head -1)"
echo "[+] arch:     $(uname -m)"
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
    GUI_APP="${BUILD_DIR}/bin/rop_scanner_gui.app"
    if [ -d "${GUI_APP}" ]; then
        echo "[+] GUI → ${GUI_APP}    (open '${GUI_APP}' to launch)"
    fi
fi

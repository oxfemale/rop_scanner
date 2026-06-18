cmake_minimum_required(VERSION 3.16)
project(rop_scanner CXX)

option(BUILD_GUI "Build the Qt-based GUI front-end" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Single executable name, cross-platform output dir.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /EHsc)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wno-multichar)
endif()

# ---------------------------------------------------------------------------
# Zydis (third-party, fetched at configure time)
# ---------------------------------------------------------------------------
include(FetchContent)

set(ZYDIS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS      OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
    GIT_SHALLOW    TRUE
    SOURCE_DIR     ${CMAKE_SOURCE_DIR}/third_party/zydis
)
FetchContent_MakeAvailable(zydis)

# ---------------------------------------------------------------------------
# rop_scanner
# ---------------------------------------------------------------------------
add_executable(rop_scanner
    src/main.cpp
    src/pe_loader.cpp
    src/scanner.cpp
    src/gadget.cpp
    src/symbol_resolver.cpp
    src/output_text.cpp
    src/output_json.cpp
    src/output_ropper.cpp
    src/output_pwntools.cpp
)

target_include_directories(rop_scanner PRIVATE src)
target_link_libraries(rop_scanner PRIVATE Zydis)

# Windows: dbghelp for PDB resolution.
if(WIN32)
    target_link_libraries(rop_scanner PRIVATE dbghelp)
endif()

# gcc < 9 split <filesystem> into libstdc++fs.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    target_link_libraries(rop_scanner PRIVATE stdc++fs)
endif()

# Apple clang < 11 split <filesystem> into libc++fs.
if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 11.0)
    target_link_libraries(rop_scanner PRIVATE c++fs)
endif()

install(TARGETS rop_scanner RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Optional GUI front-end (Qt6 with Qt5 fallback)
# ---------------------------------------------------------------------------
if(BUILD_GUI)
    add_subdirectory(gui)
endif()

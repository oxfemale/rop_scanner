cmake_minimum_required(VERSION 3.16)

# Prefer Qt6, fall back to Qt5.
find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(GUI_SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/ScannerRunner.cpp
)
set(GUI_HEADERS
    src/MainWindow.h
    src/ScannerRunner.h
)

if(WIN32)
    add_executable(rop_scanner_gui WIN32 ${GUI_SOURCES} ${GUI_HEADERS})
elseif(APPLE)
    add_executable(rop_scanner_gui MACOSX_BUNDLE ${GUI_SOURCES} ${GUI_HEADERS})
else()
    add_executable(rop_scanner_gui              ${GUI_SOURCES} ${GUI_HEADERS})
endif()

target_link_libraries(rop_scanner_gui PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

set_target_properties(rop_scanner_gui PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME    "rop_scanner"
    MACOSX_BUNDLE_GUI_IDENTIFIER "io.github.oxfemale.rop-scanner"
)

message(STATUS "GUI: building rop_scanner_gui (Qt${QT_VERSION_MAJOR})")

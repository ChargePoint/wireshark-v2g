#
# WireShark Dissectors to Support Debug/Development of the V2G
# protocols (ISO 15118) standards.
#
cmake_minimum_required (VERSION 3.5)
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "Please remove CMakeCache.txt and the CMakeFiles/ "
                        "directory then build out-of-source.")
endif()

# NOTE: The wireshark plugin build assumes major.minor.patch.tweak
project(wireshark-v2g VERSION 0.1.0.0)

# Set the default C/C++ standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add some cmake modules
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(BuildType)

# Add external dependencies (should be included first)
include(extern/dependencies.cmake)

set(PLUGIN_FILES
    src/packet-v2gexi.c
    src/packet-v2gdin.c
    src/packet-v2giso1.c
)

set_source_files_properties(${PLUGIN_FILES}
    PROPERTIES
        COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

# Add the wireshark plugins
find_package(Wireshark)

if(Wireshark_FOUND)

    message(STATUS "Wireshark found in ${Wireshark_LIB_DIR}")

    if(NOT CMAKE_INSTALL_LIBDIR)
        set(CMAKE_INSTALL_LIBDIR ~/.local/lib/wireshark/plugins/${Wireshark_VERSION_MAJOR}.${Wireshark_VERSION_MINOR}/epan)
    endif()

    include(UseMakePluginReg)

    add_definitions(-DPLUGIN_VERSION=\"${CMAKE_PROJECT_VERSION}\")
    add_compile_options(-Wall -Werror)

    find_package(GLIB2 2.4.0)
    include_directories(${GLIB2_INCLUDE_DIRS})

    include_directories(${Wireshark_INCLUDE_DIR})
    link_directories(${Wireshark_LIB_DIR})
    if(APPLE)
        link_directories(/usr/local/lib)
    endif(APPLE)

    # Keep in sync with in-tree build
    register_plugin_files(plugin.c
        plugin
        ${PLUGIN_FILES}
    )

    add_library(v2gexi MODULE
        plugin.c
        ${PLUGIN_FILES}
        ${PLUGIN_RC_FILE}
    )

    set_target_properties(v2gexi
        PROPERTIES
            PREFIX ""
            LINK_FLAGS "${WS_LINK_FLAGS}"
            FOLDER "Plugins"
    )

    target_link_libraries(v2gexi wireshark openv2g)

    install(TARGETS v2gexi
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

else(Wireshark_FOUND)

    message(STATUS "In-tree Wireshark plug-in build")

    include(WiresharkPlugin)

    # Plugin name and version info (major minor micro extra)
    set_module_info(v2gexi
        ${PROJECT_VERSION_MAJOR}
        ${PROJECT_VERSION_MINOR}
        ${PROJECT_VERSION_PATCH}
        ${PROJECT_VERSION_TWEAK}
    )

    # Keep in sync with standalone build
    register_plugin_files(plugin.c
        plugin
        ${PLUGIN_FILES}
    )

    add_plugin_library(v2gexi epan)
    target_link_libraries(v2gexi epan openv2g)

    file(GLOB PLUGIN_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
    CHECKAPI(
        NAME
            v2gexi
        SWITCHES
            -g abort -g termoutput
        SOURCES
            ${PLUGIN_FILES}
            ${PLUGIN_HEADERS}
    )

endif(Wireshark_FOUND)

# Install dissectors written by hand (lua)
add_subdirectory(dissector)

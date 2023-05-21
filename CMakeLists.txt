#
# WireShark Dissectors to Support Debug/Development of the V2G
# protocols (ISO 15118) standards.
#
cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)

if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "Please remove CMakeCache.txt and the CMakeFiles/ "
                        "directory then build out-of-source.")
endif()

# NOTE: The wireshark plugin build assumes major.minor.patch.tweak
project(wireshark-v2g VERSION 0.6.1.0)

# Set the default C/C++ standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
if(APPLE)
    set(CMAKE_MACOSX_RPATH True)
    set(CMAKE_SKIP_BUILD_RPATH False)
    set(CMAKE_INSTALL_NAME_DIR "@rpath/")
    set(CMAKE_BUILD_WITH_INSTALL_RPATH False)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH False)
endif()

# Add some cmake modules
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(BuildType)

# Add external dependencies (should be included first)
include(extern/dependencies.cmake)

set(DISSECTOR_SRC
    src/packet-v2gexi.c
    src/packet-v2gdin.c
    src/packet-v2giso1.c
    src/packet-v2giso2.c
)

set_source_files_properties(${DISSECTOR_SRC}
    PROPERTIES
        COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

# Add the wireshark plugins
find_package(Wireshark)

if(Wireshark_FOUND)

    message(STATUS "Wireshark found in ${Wireshark_LIB_DIR}")

    if(NOT Wireshark_PLUGINS_ENABLED)
        message(WARNING "Wireshark was compiled without support for plugins")
    endif()

    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
            CACHE PATH "Installation prefix" FORCE)
    endif()

    # External plugins must define HAVE_SSIZE_T for the plugin toolchain.
    include(CheckTypeSize)
    check_type_size("ssize_t" SSIZE_T)

    add_compile_definitions(
        VERSION=\"${CMAKE_PROJECT_VERSION}\"
        $<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
    )
    add_compile_options(-Wall -Werror)

    find_package(GLIB2 2.4.0)
    include_directories(${GLIB2_INCLUDE_DIRS})

    include_directories(${Wireshark_INCLUDE_DIR})
    link_directories(${Wireshark_LIB_DIR})
    if(APPLE)
        link_directories(/usr/local/lib)
    endif(APPLE)

    add_library(v2gexi MODULE
        src/v2gplugin.c
        ${DISSECTOR_SRC}
    )

    set_target_properties(v2gexi
        PROPERTIES
            PREFIX ""
            DEFINE_SYMBOL ""
            LINK_FLAGS "${WS_LINK_FLAGS}"
            FOLDER "Plugins"
    )

    target_link_libraries(v2gexi epan openv2g ${GLIB2_LIBRARY})

    install(TARGETS v2gexi
        LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
    )
    install(FILES dissector/v2g.lua
        DESTINATION "${Wireshark_PLUGIN_LIBDIR}/.." NAMELINK_SKIP
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

    set(PLUGIN_FILES
        plugin.c
        ${DISSECTOR_SRC}
    )

    # Keep in sync with standalone build
    register_plugin_files(plugin.c
        plugin
        ${DISSECTOR_SRC}
    )

    add_wireshark_plugin_library(v2gexi epan)
    target_link_libraries(v2gexi epan openv2g)
    install_plugin(v2gexi epan)
    install(FILES dissector/v2g.lua
            DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}/epan NAMELINK_SKIP
    )

    if(APPLE)
        add_custom_target(v2glua
            COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/dissector/v2g.lua
                ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/PlugIns/wireshark
            DEPENDS v2gexi
        )
        add_dependencies(plugins v2glua)
    endif()

    file(GLOB PLUGIN_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
    CHECKAPI(
        NAME
            v2gexi
        SWITCHES
            -g abort -g termoutput
        SOURCES
            ${DISSECTOR_SRC}
            ${DISSECTOR_HEADERS}
    )

endif(Wireshark_FOUND)

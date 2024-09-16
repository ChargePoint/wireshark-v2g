# Add external projects that will be used for the build
include(FetchContent)

#
# Use the libcbv2g project as part of the dissector
#
set(libcbv2g_VERSION 0.2.0)
set(LIBCBV2G_PATCH_COMMAND patch -p1)

FetchContent_Declare(libcbv2g
    GIT_REPOSITORY https://github.com/EVerest/libcbv2g.git
    GIT_TAG v${libcbv2g_VERSION}
    GIT_SHALLOW ON
    PATCH_COMMAND ${LIBCBV2G_PATCH_COMMAND} < ${PROJECT_SOURCE_DIR}/extern/libcbv2g-to-build-standalone.patch
          COMMAND ${LIBCBV2G_PATCH_COMMAND} < ${PROJECT_SOURCE_DIR}/extern/libcbv2g-add-static-and-position-independent-code.patch
    CMAKE_ARGS -DCB_V2G_BUILD_TESTS:BOOL=OFF
)

FetchContent_MakeAvailable(libcbv2g)
FetchContent_GetProperties(libcbv2g)

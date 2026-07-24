# Add external projects that will be used for the build
include(FetchContent)

#
# Use the libcbv2g project as part of the dissector
#
set(LIBCBV2G_PATCH_COMMAND patch -p1)

FetchContent_Declare(libcbv2g
    GIT_REPOSITORY https://github.com/EVerest/libcbv2g.git
    GIT_TAG 03350be048b35b179905129005a97144a4bdcf93
    PATCH_COMMAND ${LIBCBV2G_PATCH_COMMAND} < ${PROJECT_SOURCE_DIR}/extern/libcbv2g-add-static-and-position-independent-code.patch
    COMMAND ${LIBCBV2G_PATCH_COMMAND} < ${PROJECT_SOURCE_DIR}/extern/libcbv2g-fix-iso20-secp521-buffer-size.patch
    CMAKE_ARGS -DCB_V2G_BUILD_TESTS:BOOL=OFF
)

FetchContent_MakeAvailable(libcbv2g)
FetchContent_GetProperties(libcbv2g)

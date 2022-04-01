# Add external projects that will be used for the build
include(FetchContent)

#
# Use the OpenV2G project as part of the dissector
#
set(openv2g_VERSION 0.9.5)
FetchContent_Declare(openv2g
    URL https://sourceforge.net/projects/openv2g/files/release/OpenV2G_${openv2g_VERSION}/OpenV2G_${openv2g_VERSION}.zip/download
    URL_HASH SHA1=c9486c0393346717dafc4df7f2b97c5426f22c43
)

FetchContent_MakeAvailable(openv2g)
FetchContent_GetProperties(openv2g)

add_library(openv2g STATIC
    ${openv2g_SOURCE_DIR}/src/appHandshake/appHandEXIDatatypes.c
    ${openv2g_SOURCE_DIR}/src/appHandshake/appHandEXIDatatypesDecoder.c
    ${openv2g_SOURCE_DIR}/src/appHandshake/appHandEXIDatatypesEncoder.c 

    ${openv2g_SOURCE_DIR}/src/codec/BitInputStream.c
    ${openv2g_SOURCE_DIR}/src/codec/BitOutputStream.c
    ${openv2g_SOURCE_DIR}/src/codec/ByteStream.c
    ${openv2g_SOURCE_DIR}/src/codec/DecoderChannel.c
    ${openv2g_SOURCE_DIR}/src/codec/EXIHeaderDecoder.c
    ${openv2g_SOURCE_DIR}/src/codec/EXIHeaderEncoder.c
    ${openv2g_SOURCE_DIR}/src/codec/EncoderChannel.c
    ${openv2g_SOURCE_DIR}/src/codec/MethodsBag.c 

    ${openv2g_SOURCE_DIR}/src/din/dinEXIDatatypes.c
    ${openv2g_SOURCE_DIR}/src/din/dinEXIDatatypesDecoder.c
    ${openv2g_SOURCE_DIR}/src/din/dinEXIDatatypesEncoder.c 

    ${openv2g_SOURCE_DIR}/src/iso1/iso1EXIDatatypes.c
    ${openv2g_SOURCE_DIR}/src/iso1/iso1EXIDatatypesDecoder.c
    ${openv2g_SOURCE_DIR}/src/iso1/iso1EXIDatatypesEncoder.c 

    ${openv2g_SOURCE_DIR}/src/iso2/iso2EXIDatatypes.c
    ${openv2g_SOURCE_DIR}/src/iso2/iso2EXIDatatypesDecoder.c
    ${openv2g_SOURCE_DIR}/src/iso2/iso2EXIDatatypesEncoder.c

    ${openv2g_SOURCE_DIR}/src/xmldsig/xmldsigEXIDatatypes.c
    ${openv2g_SOURCE_DIR}/src/xmldsig/xmldsigEXIDatatypesDecoder.c
    ${openv2g_SOURCE_DIR}/src/xmldsig/xmldsigEXIDatatypesEncoder.c

    # transport (unused)
    #${openv2g_SOURCE_DIR}/src/transport/v2gtp.c
)
target_include_directories(openv2g
    PUBLIC
        ${openv2g_SOURCE_DIR}/src/appHandshare
        ${openv2g_SOURCE_DIR}/src/codec
        ${openv2g_SOURCE_DIR}/src/din
        ${openv2g_SOURCE_DIR}/src/iso1
        ${openv2g_SOURCE_DIR}/src/iso2
        ${openv2g_SOURCE_DIR}/src/xmldsig

        #${openv2g_SOURCE_DIR}/src/transport
)

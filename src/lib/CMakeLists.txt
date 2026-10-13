add_library(decoder SHARED decoder.cpp decoder.def)

target_include_directories(decoder PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(decoder PRIVATE ole32 oleaut32)

if(DECODER_ENABLE_DEBUG_LOGS)
    target_compile_definitions(decoder PRIVATE DECODER_DEBUG=1)
endif()

if(MSVC)
    target_compile_options(decoder PRIVATE /W3 /EHsc)
endif()

set_target_properties(decoder PROPERTIES
    PREFIX ""
    OUTPUT_NAME "decoder"
)

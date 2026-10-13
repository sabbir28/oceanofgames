add_executable(test_decoder test_decoder.c)

target_include_directories(test_decoder PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(test_decoder PRIVATE /W3)
endif()

add_dependencies(test_decoder decoder)

add_test(NAME verify_abi_exports
    COMMAND test_decoder -d $<TARGET_FILE:decoder>
)

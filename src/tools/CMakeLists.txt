add_executable(standalone_extractor standalone_extractor.c)

target_include_directories(standalone_extractor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(standalone_extractor PRIVATE /W3)
endif()

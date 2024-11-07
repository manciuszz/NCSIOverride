cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(NCSIOverride VERSION 1.0 LANGUAGES CXX)

add_library(NCSIOverride SHARED NCSIOverride.cpp)

set_target_properties(NCSIOverride PROPERTIES
    OUTPUT_NAME "NCSIOverride"
)

# Add include directories for MinHook
target_include_directories(NCSIOverride PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/MinHook
)

# Link MinHook
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message("Linking MinHook x64")
    target_link_libraries(NCSIOverride PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/MinHook/libMinHook.x64.lib
    )
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message("Linking MinHook x86")
    target_link_libraries(NCSIOverride PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/MinHook/libMinHook.x86.lib
    )
endif()

# Set compiler options for Visual Studio
if(MSVC)
    target_compile_options(NCSIOverride PRIVATE /W4)
endif()

set_target_properties(NCSIOverride PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

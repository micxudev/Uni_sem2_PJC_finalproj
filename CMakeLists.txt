cmake_minimum_required(VERSION 3.28)
project(Project_image_steganography)
set(CMAKE_CXX_STANDARD 20)
include(FetchContent)
FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt
        GIT_TAG 10.2.1
)
FetchContent_MakeAvailable(fmt)
add_executable(Project_image_steganography main.cpp)
target_link_libraries(Project_image_steganography fmt)
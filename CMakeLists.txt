cmake_minimum_required(VERSION 3.25)
project(cssl C)

set(CMAKE_C_STANDARD 99)

include_directories(include)

find_package(OpenSSL REQUIRED)

add_library(cssl STATIC library.c
        src/cssl.c
)

target_include_directories(cssl PUBLIC include)

target_link_libraries(cssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)
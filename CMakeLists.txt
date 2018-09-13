cmake_minimum_required(VERSION 3.2)    
project(udpreplay CXX)

set(CMAKE_CXX_STANDARD 11)

add_executable(udpreplay src/udpreplay.cpp)
target_compile_options(udpreplay PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(udpreplay pcap)

install(TARGETS udpreplay DESTINATION bin/)

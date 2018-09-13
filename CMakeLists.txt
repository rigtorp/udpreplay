cmake_minimum_required(VERSION 3.2)    
project(udpreplay CXX)

set(CMAKE_CXX_STANDARD 11)

find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(udpreplay src/udpreplay.cpp)
target_compile_options(udpreplay PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(udpreplay ${PCAP_LIBRARIES})
target_include_directories(udpreplay PRIVATE ${PCAP_INCLUDE_DIRS})

install(TARGETS udpreplay DESTINATION bin/)

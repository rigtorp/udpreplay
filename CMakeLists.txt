cmake_minimum_required(VERSION 3.2)    
project(udpreplay CXX)

set(CMAKE_CXX_STANDARD 11)

add_executable(udpreplay src/udpreplay.cpp)
target_compile_options(udpreplay PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(udpreplay pcap)

install(TARGETS udpreplay DESTINATION bin/)

enable_testing()

add_test(constant-interval ${CMAKE_SOURCE_DIR}/test/constant-interval.expect -f)

add_test(high-speed ${CMAKE_SOURCE_DIR}/test/high-speed.expect -f)

add_test(low-speed ${CMAKE_SOURCE_DIR}/test/low-speed.expect -f)

add_test(normal-speed ${CMAKE_SOURCE_DIR}/test/normal-speed.expect -f)

add_test(concurrent/basic ${CMAKE_SOURCE_DIR}/test/concurrent/basic.sh)

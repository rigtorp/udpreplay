cmake_minimum_required(VERSION 3.2)    
project(udpreplay)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

add_executable(udpreplay udpreplay.cpp)
target_link_libraries(udpreplay -lpcap)

install(TARGETS udpreplay DESTINATION bin/)

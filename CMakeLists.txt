cmake_minimum_required(VERSION 3.20)
project(udpreplay VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME MATCHES "^(Linux|Darwin)$")
  message(FATAL_ERROR "udpreplay supports Linux and macOS")
endif()

option(UDPREPLAY_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(_testing_default OFF)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  set(_testing_default ON)
endif()
option(BUILD_TESTING "Enable packet and timing tests" ${_testing_default})

# Homebrew's keg-only libpcap is not on the default compiler search path.
set(_pcap_prefixes)
if(APPLE AND NOT CMAKE_CROSSCOMPILING)
  find_program(HOMEBREW_EXECUTABLE NAMES brew)
  if(HOMEBREW_EXECUTABLE)
    execute_process(COMMAND "${HOMEBREW_EXECUTABLE}" --prefix libpcap
      OUTPUT_VARIABLE _pcap_prefix OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE _pcap_result ERROR_QUIET TIMEOUT 10)
    if(_pcap_result EQUAL 0)
      list(APPEND _pcap_prefixes "${_pcap_prefix}")
    endif()
  endif()
endif()
find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h
  HINTS ${_pcap_prefixes} PATH_SUFFIXES include REQUIRED)
find_library(PCAP_LIBRARY NAMES pcap
  HINTS ${_pcap_prefixes} PATH_SUFFIXES lib REQUIRED)
mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
add_library(PCAP::PCAP UNKNOWN IMPORTED)
set_target_properties(PCAP::PCAP PROPERTIES
  IMPORTED_LOCATION "${PCAP_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}")

add_executable(udpreplay src/udpreplay.cpp)
set_target_properties(udpreplay PROPERTIES
  CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_link_libraries(udpreplay PRIVATE PCAP::PCAP)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(udpreplay PRIVATE -Wall -Wextra -Wpedantic)
  if(UDPREPLAY_WARNINGS_AS_ERRORS)
    target_compile_options(udpreplay PRIVATE -Werror)
  endif()
endif()

include(GNUInstallDirs)
install(TARGETS udpreplay RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME packet-validation
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test/packet-validation.py"
      "$<TARGET_FILE:udpreplay>")
  set_tests_properties(packet-validation PROPERTIES TIMEOUT 30)

  foreach(test IN ITEMS constant-interval constant-interval-ge1 high-speed
                        low-speed normal-speed)
    add_test(NAME ${test}
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test/timing-validation.py"
        "$<TARGET_FILE:udpreplay>" "${CMAKE_CURRENT_SOURCE_DIR}/test/test.pcap"
        "${test}")
    set_tests_properties(${test} PROPERTIES TIMEOUT 20)
  endforeach()
endif()

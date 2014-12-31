cmake_minimum_required(VERSION 2.8.8)
project(OSQUERY)

if(APPLE)
  set(APPLE_MIN_ABI "10.9")
  set(OS_COMPILE_FLAGS "-std=c++11 -stdlib=libc++ -mmacosx-version-min=${APPLE_MIN_ABI}")
  # Special compile flags for Objective-C++
  set(OBJCXX_COMPILE_FLAGS "-x objective-c++ -fobjc-arc -Wno-c++11-extensions")
  set(OS_WHOLELINK_PRE "-Wl,-force_load")
  set(OS_WHOLELINK_POST "")
else()
  if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
    set(OS_COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
    set(OS_WHOLELINK_PRE "")
    set(OS_WHOLELINK_POST "")
  else()
    set(LINUX TRUE)
    set(OS_COMPILE_FLAGS "-std=c++11")
    set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
    set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
  endif()
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(OS_COMPILE_FLAGS "${OS_COMPILE_FLAGS} -g -DDEBUG -O0")
else()
  set(OS_COMPILE_FLAGS "${OS_COMPILE_FLAGS} -O2")
endif()

# Use osquery language to set platform/os
execute_process(
  COMMAND "${CMAKE_SOURCE_DIR}/tools/provision.sh" get_platform
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE PLATFORM
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REPLACE "." "_" PLATFORM "${PLATFORM}")
string(TOUPPER "${PLATFORM}" PLATFORM)
list(GET PLATFORM 0 OSQUERY_BUILD_OS)
list(GET PLATFORM 1 OSQUERY_BUILD_DISTRO)

# Make sure deps were built before compiling
execute_process(
  COMMAND "${CMAKE_SOURCE_DIR}/tools/provision.sh" check "${CMAKE_BINARY_DIR}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE OSQUERY_DEPS_MESSAGE
  RESULT_VARIABLE OSQUERY_DEPS_CHECK
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(OSQUERY_DEPS_CHECK)
  string(ASCII 27 Esc)
  message(WARNING "${Esc}[31m${OSQUERY_DEPS_MESSAGE}${Esc}[m")
endif()

if(APPLE)
  message("-- Building for OS X")
elseif(OSQUERY_BUILD_OS STREQUAL "UBUNTU")
  set(UBUNTU TRUE)
  message("-- Building for Ubuntu")
elseif(OSQUERY_BUILD_OS STREQUAL "CENTOS")
  set(CENTOS TRUE)
  message("-- Building for CentOS")
elseif(FREEBSD)
  message("-- Building for FreeBSD")
endif()

set(USER_COMPILE_FLAGS "-static")
set(OS_COMPILE_FLAGS "${OS_COMPILE_FLAGS} ${USER_COMPILE_FLAGS}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" "${CMAKE_MODULE_PATH}")
find_package(Gtest REQUIRED)
find_package(Sqlite3 REQUIRED)
find_package(BZip2 REQUIRED)
find_package(Glog REQUIRED)
find_package(Gflags REQUIRED)
find_package(Thrift 0.9.1 REQUIRED)
find_package(Readline REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Snappy REQUIRED)
find_package(RocksDB REQUIRED)
find_package(Crypto REQUIRED)
find_package(Dl REQUIRED)
if(NOT APPLE)
  find_package(Unwind REQUIRED)
  find_package(LZMA REQUIRED)
endif()

include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_SOURCE_DIR}")
include_directories("/usr/local/include")
link_directories("/usr/local/lib")

enable_testing()

include(CMakeLibs)
add_subdirectory(osquery)
add_subdirectory(tools/tests)

# make docs
find_package(Doxygen)
if(DOXYGEN_FOUND)
  add_custom_target(
    docs
    "${DOXYGEN_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/Doxyfile"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Generating API documentation with Doxygen" VERBATIM
  )
endif(DOXYGEN_FOUND)

# make format-all
add_custom_target(
  format-all
  find osquery include tools \( -name "*.h" -o -name "*.cpp" -o -name "*.mm" \) -exec clang-format -i {} +
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Formatting all osquery code with clang-format" VERBATIM
)

add_custom_target(
  format
  python "${CMAKE_SOURCE_DIR}/tools/formatting/git-clang-format.py"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Formatting code staged code changes with clang-format" VERBATIM
)

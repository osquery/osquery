CMAKE_MINIMUM_REQUIRED(VERSION 2.8.8)
PROJECT(OSQUERY)

if(APPLE)
  set(APPLE_MIN_ABI "10.9")
  set(OS_COMPILE_FLAGS "-std=c++11 -stdlib=libc++ -mmacosx-version-min=${APPLE_MIN_ABI}")
  set(OS_WHOLELINK_PRE "-Wl,-all_load")
  set(OS_WHOLELINK_POST "")
else()
  if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
    set(OS_COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
    set(OS_WHOLELINK_PRE "")
    set(OS_WHOLELINK_POST "")
  else()
    set(LINUX TRUE)
    set(OS_COMPILE_FLAGS "-std=c++11 -DTHREADED")
    set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
    set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
  endif()
  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(OS_COMPILE_FLAGS "${OS_COMPILE_FLAGS} -g -DDEBUG")
  endif()
endif()

# Use osquery language to set platform/os
execute_process(
  COMMAND ${CMAKE_SOURCE_DIR}/tools/provision.sh get_platform
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE PLATFORM
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REPLACE "." "_" PLATFORM "${PLATFORM}")
string(TOUPPER "${PLATFORM}" PLATFORM)
list(GET PLATFORM 0 OSQUERY_BUILD_OS)
list(GET PLATFORM 1 OSQUERY_BUILD_DISTRO)

# Make sure deps were built before compiling
execute_process(
  COMMAND ${CMAKE_SOURCE_DIR}/tools/provision.sh check ${CMAKE_BINARY_DIR}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
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

if(BUILD_SHARED_LIBS)
  set(USER_COMPILE_FLAGS "-fPIC")
else()
  # Building/linking statically (no libosquery)
  set(USER_COMPILE_FLAGS "-static")
endif()

set(OS_COMPILE_FLAGS "${OS_COMPILE_FLAGS} ${USER_COMPILE_FLAGS}")

SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})
FIND_PACKAGE(Gtest REQUIRED)
FIND_PACKAGE(Sqlite3 REQUIRED)
FIND_PACKAGE(BZip2 REQUIRED)
FIND_PACKAGE(Glog REQUIRED)
FIND_PACKAGE(Gflags REQUIRED)
FIND_PACKAGE(Thrift 0.9.1 REQUIRED)
FIND_PACKAGE(Readline REQUIRED)
FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(Snappy REQUIRED)
FIND_PACKAGE(RocksDB REQUIRED)
FIND_PACKAGE(Crypto REQUIRED)
FIND_PACKAGE(Dl REQUIRED)
if(NOT APPLE)
  FIND_PACKAGE(Unwind REQUIRED)
  FIND_PACKAGE(LZMA REQUIRED)
endif()

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/include")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}")
INCLUDE_DIRECTORIES("/usr/local/include")
INCLUDE_DIRECTORIES("/usr/include")
LINK_DIRECTORIES("/usr/local/lib")

ENABLE_TESTING()

ADD_SUBDIRECTORY(osquery)
ADD_SUBDIRECTORY(tools)

# make docs
FIND_PACKAGE(Doxygen)
if(DOXYGEN_FOUND)
  ADD_CUSTOM_TARGET(
    docs
    ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen" VERBATIM
  )
endif(DOXYGEN_FOUND)

# make format-all
ADD_CUSTOM_TARGET(
  format-all
  find osquery include tools \( -name "*.h" -o -name "*.cpp" -o -name "*.mm" \) -exec clang-format -i {} +
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Formatting all osquery code with clang-format" VERBATIM
)

ADD_CUSTOM_TARGET(
  format
  python tools/git-clang-format.py
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Formatting code staged code changes with clang-format" VERBATIM
)

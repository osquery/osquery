CMAKE_MINIMUM_REQUIRED(VERSION 2.8.8)
PROJECT(OSQUERY)

set(USER_COMPILE_FLAGS " ")
if(APPLE)
  set(OS_COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
  set(OS_WHOLELINK_PRE "-Wl,-all_load")
  set(OS_WHOLELINK_POST "")
else()
  set(OS_COMPILE_FLAGS "-std=c++11")
  set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
  set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
endif()

SET(BUILD_SHARED "" CACHE STRING "Build and link libosquery statically.")
if(BUILD_SHARED)
  set(USER_COMPILE_FLAGS "-fPIC")
else()
  # Building/linking statically (no libosquery)
endif()

set(OS_COMPILE_FLAGS "${OS_COMPILE_FLAGS} ${USER_COMPILE_FLAGS}")

SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})
FIND_PACKAGE(Gtest REQUIRED)
FIND_PACKAGE(Sqlite3 REQUIRED)

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/include")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}")
INCLUDE_DIRECTORIES("/usr/local/include")
LINK_DIRECTORIES("/usr/local/lib")


ENABLE_TESTING()

ADD_SUBDIRECTORY(osquery)
ADD_SUBDIRECTORY(tools)

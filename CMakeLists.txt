CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(OSQUERY)

INCLUDE_DIRECTORIES("/usr/local/include")
LINK_DIRECTORIES("/usr/local/lib")

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}")

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/gtest-1.7.0/include")
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/third-party/gtest-1.7.0")

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/rocksdb/include")
include(ExternalProject)
ExternalProject_Add(librocksdb
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/rocksdb"
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make shared_lib && make static_lib
  INSTALL_COMMAND cp librocksdb.dylib /usr/local/lib/librocksdb.dylib && cp librocksdb.a /usr/local/lib/librocksdb.a
)

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/third-party/sqlite3")
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/third-party/sqlite3")

SET(GEN_TABLE_PATH "${CMAKE_SOURCE_DIR}/tools/gentable.py")

ADD_SUBDIRECTORY(osquery/config)
ADD_SUBDIRECTORY(osquery/core)
ADD_SUBDIRECTORY(osquery/database)
ADD_SUBDIRECTORY(osquery/devtools)
ADD_SUBDIRECTORY(osquery/filesystem)
ADD_SUBDIRECTORY(osquery/logger)
ADD_SUBDIRECTORY(osquery/scheduler)
ADD_SUBDIRECTORY(osquery/tables)

SET(OSQUERY_LIBS
  gflags
  glog
  osquery_config
  osquery_core
  osquery_database
  osquery_devtools
  osquery_filesystem
  osquery_logger
  osquery_scheduler
  osquery_sqlite
  osquery_tables
)

ADD_LIBRARY(osquery_static osquery/main/lib.cpp)
TARGET_LINK_LIBRARIES(osquery_static ${OSQUERY_LIBS})
SET_TARGET_PROPERTIES(osquery_static PROPERTIES OUTPUT_NAME osquery)

ADD_EXECUTABLE(shell osquery/main/shell.cpp)
TARGET_LINK_LIBRARIES(shell osquery_static)
SET_TARGET_PROPERTIES(shell PROPERTIES OUTPUT_NAME osqueryi)
SET_TARGET_PROPERTIES(shell PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
INSTALL(TARGETS shell DESTINATION bin)

ADD_EXECUTABLE(daemon osquery/main/daemon.cpp)
TARGET_LINK_LIBRARIES(daemon osquery_static)
TARGET_LINK_LIBRARIES(daemon "-framework CoreFoundation")
SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME osqueryd)
SET_TARGET_PROPERTIES(daemon PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
INSTALL(TARGETS daemon DESTINATION bin)

ADD_SUBDIRECTORY(tools)

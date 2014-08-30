CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(OSQUERY)

SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})
FIND_PACKAGE(Gtest REQUIRED)
FIND_PACKAGE(RocksDB REQUIRED)
FIND_PACKAGE(Sqlite3 REQUIRED)

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}")
INCLUDE_DIRECTORIES("/usr/local/include")

LINK_DIRECTORIES("/usr/local/lib")

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
SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME osqueryd)
SET_TARGET_PROPERTIES(daemon PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
INSTALL(TARGETS daemon DESTINATION bin)

ADD_SUBDIRECTORY(tools)

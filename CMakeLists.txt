CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(OSQUERY)

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}")

SET(CMAKE_C_FLAGS "-std=c99 -static -static-libgcc")
SET(CMAKE_CXX_FLAGS "-std=c++11 -static -static-libgcc -static-libstdc++")
SET(CMAKE_LIBRARY_PATH "/usr/local/lib:/usr/lib:/usr/lib64")

ADD_SUBDIRECTORY(osquery/config)
ADD_SUBDIRECTORY(osquery/core)
ADD_SUBDIRECTORY(osquery/database)
ADD_SUBDIRECTORY(osquery/devtools)
ADD_SUBDIRECTORY(osquery/logger)
ADD_SUBDIRECTORY(osquery/scheduler)
ADD_SUBDIRECTORY(osquery/sqlite)
ADD_SUBDIRECTORY(osquery/tables)

SET(OSQUERY_LIBS
  gflags
  glog
  osquery_config
  osquery_core
  osquery_database
  osquery_devtools
  osquery_logger
  osquery_scheduler
  osquery_sqlite
  osquery_tables
)

ADD_LIBRARY(osquery_static osquery/main/lib.cpp)
TARGET_LINK_LIBRARIES(osquery_static ${OSQUERY_LIBS})
SET_TARGET_PROPERTIES(osquery_static PROPERTIES OUTPUT_NAME osquery)

ADD_LIBRARY(osquery_dynamic SHARED osquery/main/lib.cpp)
TARGET_LINK_LIBRARIES(osquery_dynamic ${OSQUERY_LIBS})
SET_TARGET_PROPERTIES(osquery_dynamic PROPERTIES OUTPUT_NAME osquery)

ADD_EXECUTABLE(shell osquery/main/shell.cpp)
TARGET_LINK_LIBRARIES(shell osquery_static)
SET_TARGET_PROPERTIES(shell PROPERTIES OUTPUT_NAME osqueryi)
INSTALL(TARGETS shell DESTINATION bin)

ADD_EXECUTABLE(daemon osquery/main/daemon.cpp)
TARGET_LINK_LIBRARIES(daemon osquery_static)
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  #TARGET_LINK_LIBRARIES(daemon rt)
endif()
SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME osqueryd)
INSTALL(TARGETS daemon DESTINATION bin)

ADD_SUBDIRECTORY(config)
ADD_SUBDIRECTORY(core)
ADD_SUBDIRECTORY(database)
ADD_SUBDIRECTORY(devtools)
ADD_SUBDIRECTORY(filesystem)
ADD_SUBDIRECTORY(logger)
ADD_SUBDIRECTORY(scheduler)
ADD_SUBDIRECTORY(tables)

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

ADD_LIBRARY(osquery_static main/lib.cpp)
TARGET_LINK_LIBRARIES(osquery_static ${OSQUERY_LIBS})
SET_TARGET_PROPERTIES(osquery_static PROPERTIES OUTPUT_NAME osquery)

ADD_EXECUTABLE(shell main/shell.cpp)
TARGET_LINK_LIBRARIES(shell osquery_static)
SET_TARGET_PROPERTIES(shell PROPERTIES OUTPUT_NAME osqueryi)
SET_TARGET_PROPERTIES(shell PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
INSTALL(TARGETS shell DESTINATION bin)

ADD_EXECUTABLE(daemon main/daemon.cpp)
TARGET_LINK_LIBRARIES(daemon osquery_static)
SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME osqueryd)
SET_TARGET_PROPERTIES(daemon PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
INSTALL(TARGETS daemon DESTINATION bin)

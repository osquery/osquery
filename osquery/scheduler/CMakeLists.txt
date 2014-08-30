ADD_LIBRARY(osquery_scheduler
  scheduler.cpp
)
TARGET_LINK_LIBRARIES(osquery_scheduler glog)
TARGET_LINK_LIBRARIES(osquery_scheduler osquery_config)
TARGET_LINK_LIBRARIES(osquery_scheduler osquery_core)
TARGET_LINK_LIBRARIES(osquery_scheduler osquery_database)
TARGET_LINK_LIBRARIES(osquery_scheduler osquery_logger)
SET_TARGET_PROPERTIES(osquery_scheduler PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

ADD_LIBRARY(osquery_logger
  logger.cpp
  plugins/filesystem.cpp
)
TARGET_LINK_LIBRARIES(osquery_logger osquery_database)
TARGET_LINK_LIBRARIES(osquery_logger "-Wl,-all_load")

ADD_EXECUTABLE(logger_tests logger_tests.cpp)
TARGET_LINK_LIBRARIES(logger_tests gtest)
TARGET_LINK_LIBRARIES(logger_tests osquery_core)
TARGET_LINK_LIBRARIES(logger_tests osquery_logger)

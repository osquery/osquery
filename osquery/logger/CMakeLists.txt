ADD_OSQUERY_LIBRARY(osquery_logger
  logger.cpp
  plugins/filesystem.cpp
)

ADD_OSQUERY_TEST(logger_tests logger_tests.cpp)

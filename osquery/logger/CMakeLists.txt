ADD_LIBRARY(osquery_logger OBJECT
  logger.cpp
  plugins/filesystem.cpp
)

SET_OSQUERY_COMPILE(osquery_logger)

ADD_LIBRARY(osquery_testing_logger
  $<TARGET_OBJECTS:osquery_core>
  $<TARGET_OBJECTS:osquery_database>
  $<TARGET_OBJECTS:osquery_logger>
)

ADD_OSQUERY_TEST(logger_tests logger_tests.cpp
  osquery_testing_logger)

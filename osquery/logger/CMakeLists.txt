ADD_LIBRARY(osquery_logger
  logger.cpp
  plugins/filesystem.cpp
)
TARGET_LINK_LIBRARIES(osquery_logger osquery_database)
TARGET_LINK_LIBRARIES(osquery_logger "-Wl,-all_load")
SET_TARGET_PROPERTIES(osquery_logger PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

ADD_EXECUTABLE(logger_tests logger_tests.cpp)
TARGET_LINK_LIBRARIES(logger_tests gtest)
TARGET_LINK_LIBRARIES(logger_tests osquery_core)
TARGET_LINK_LIBRARIES(logger_tests osquery_logger)
SET_TARGET_PROPERTIES(logger_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
ADD_TEST(logger_tests logger_tests)

ADD_OSQUERY_CORE_LIBRARY(osquery_logger logger.cpp plugins/filesystem.cpp)
add_dependencies(osquery_logger libglog)

ADD_OSQUERY_TEST(logger_tests logger_tests.cpp)

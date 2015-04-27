ADD_OSQUERY_LIBRARY(TRUE osquery_logger
  logger.cpp
)
add_dependencies(osquery_logger libglog)

ADD_OSQUERY_LIBRARY(FALSE osquery_logger_plugins
  plugins/filesystem.cpp
)

file(GLOB OSQUERY_LOGGER_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_LOGGER_TESTS})

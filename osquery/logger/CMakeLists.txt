ADD_OSQUERY_LIBRARY(TRUE osquery_logger
  logger.cpp
)
add_dependencies(osquery_logger libglog)

ADD_OSQUERY_LIBRARY(FALSE osquery_logger_plugins
  plugins/filesystem.cpp
  plugins/http_logger.cpp
)

file(GLOB OSQUERY_LOGGER_TESTS "tests/*.cpp")
file(GLOB OSQUERY_LOGGER_PLUGIN_TESTS "plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_LOGGER_TESTS})
ADD_OSQUERY_TEST(FALSE ${OSQUERY_LOGGER_PLUGIN_TESTS})

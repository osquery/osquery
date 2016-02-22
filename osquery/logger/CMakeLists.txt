ADD_OSQUERY_LIBRARY(TRUE osquery_logger
  logger.cpp
)
add_dependencies(osquery_logger libglog)

ADD_OSQUERY_LIBRARY(FALSE osquery_logger_plugins
  plugins/filesystem.cpp
  plugins/tls.cpp
  plugins/syslog.cpp
)

# Keep the logger testing in the additional to test filesystem logging.
# There is a significant difference between the Glog-backed filesystem plugin
# and other, which use a Glog sink. They must be tested in tandem.
file(GLOB OSQUERY_LOGGER_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_LOGGER_TESTS})

file(GLOB OSQUERY_LOGGER_PLUGIN_TESTS "plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_LOGGER_PLUGIN_TESTS})

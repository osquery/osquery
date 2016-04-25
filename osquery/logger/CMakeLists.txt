file(GLOB OSQUERY_LOGGER "*.cpp")
ADD_OSQUERY_LIBRARY(TRUE osquery_logger ${OSQUERY_LOGGER})

file(GLOB OSQUERY_LOGGER_PLUGINS "plugins/*.cpp")
ADD_OSQUERY_LIBRARY(FALSE osquery_logger_plugins ${OSQUERY_LOGGER_PLUGINS})
ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-kinesis")
ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-firehose")
ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-core")

file(GLOB OSQUERY_LOGGER_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_LOGGER_TESTS})

# Keep the logger testing in the additional to test filesystem logging.
# There is a significant difference between the Glog-backed filesystem plugin
# and other, which use a Glog sink. They must be tested in tandem.
file(GLOB OSQUERY_LOGGER_PLUGIN_TESTS "plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_LOGGER_PLUGIN_TESTS})

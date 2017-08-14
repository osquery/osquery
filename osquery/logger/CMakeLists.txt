#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

file(GLOB OSQUERY_LOGGER "*.cpp")
ADD_OSQUERY_LIBRARY_CORE(osquery_logger ${OSQUERY_LOGGER})

file(GLOB OSQUERY_LOGGER_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST_CORE(${OSQUERY_LOGGER_TESTS})

set(OSQUERY_LOGGER_PLUGINS
  "plugins/buffered.cpp"
  "plugins/filesystem_logger.cpp"
  "plugins/tls_logger.cpp"
  "plugins/stdout.cpp"
)
if(NOT SKIP_BRO)
  LIST(APPEND OSQUERY_LOGGER_PLUGINS "plugins/bro_logger.cpp")
endif()

if(LINUX)
  list(APPEND OSQUERY_LOGGER_PLUGINS "plugins/syslog_logger.cpp")
  ADD_OSQUERY_TEST_ADDITIONAL("logger/plugins/tests/syslog_logger_tests.cpp")
endif()

ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_logger_plugins ${OSQUERY_LOGGER_PLUGINS})

set(OSQUERY_LOGGER_PLUGIN_TESTS
  "logger/plugins/tests/filesystem_logger_tests.cpp"
  "logger/plugins/tests/buffered_tests.cpp"
  "logger/plugins/tests/tls_logger_tests.cpp"
)

# Keep the logger testing in the additional to test filesystem logging.
# There is a significant difference between the Glog-backed filesystem plugin
# and others, which use a Glog sink. They must be tested in tandem.
ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_LOGGER_PLUGIN_TESTS})

if(NOT SKIP_AWS AND NOT WINDOWS)
  set(OSQUERY_LOGGER_AWS_PLUGINS
    "plugins/aws_firehose.cpp"
    "plugins/aws_kinesis.cpp"
  )

  ADD_OSQUERY_LIBRARY_ADDITIONAL(
    osquery_logger_aws_plugins
    ${OSQUERY_LOGGER_AWS_PLUGINS}
  )

  set(OSQUERY_LOGGER_AWS_PLUGIN_TESTS
    "logger/plugins/tests/aws_firehose_tests.cpp"
    "logger/plugins/tests/aws_kinesis_tests.cpp"
  )

  ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_LOGGER_AWS_PLUGIN_TESTS})

  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-kinesis")
  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-firehose")
endif()

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

file(GLOB OSQUERY_LOGGER "*.cpp")

if(WINDOWS)
  # The Windows Event Log plugin is also used for the built-in systemLog call. This
  # is why we are listing it as a core source file.
  list(APPEND OSQUERY_LOGGER "plugins/windows_event_log.cpp")
endif()

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

file(GLOB OSQUERY_LOGGER_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_LOGGER_BENCHMARKS})

if(NOT SKIP_KAFKA AND NOT WINDOWS AND NOT FREEBSD)
  set(OSQUERY_LOGGER_KAFKA_PLUGINS
    "plugins/kafka_producer.cpp"
  )

  ADD_OSQUERY_LIBRARY_ADDITIONAL(
    osquery_logger_kafka_plugins
    ${OSQUERY_LOGGER_KAFKA_PLUGINS}
  )

  ADD_OSQUERY_LINK_ADDITIONAL("rdkafka")

  set(OSQUERY_LOGGER_KAFKA_PLUGINS_TESTS
    "logger/plugins/tests/kafka_producer_tests.cpp"
  )

  ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_LOGGER_KAFKA_PLUGINS_TESTS})
endif()

if(NOT SKIP_AWS)
  set(OSQUERY_LOGGER_AWS_PLUGINS
    "plugins/aws_firehose.cpp"
    "plugins/aws_kinesis.cpp"
  )

  ADD_OSQUERY_LIBRARY_ADDITIONAL(
    osquery_logger_aws_plugins
    ${OSQUERY_LOGGER_AWS_PLUGINS}
  )

  set(OSQUERY_LOGGER_AWS_PLUGIN_TESTS
    "logger/plugins/tests/aws_logger_tests.cpp"
  )

  ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_LOGGER_AWS_PLUGIN_TESTS})

  if(WINDOWS)
    ADD_OSQUERY_LINK_CORE("UserEnv.lib")
    ADD_OSQUERY_LINK_CORE("bcrypt.lib")
    ADD_OSQUERY_LINK_CORE("wevtapi.lib")
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-kinesis")
  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-firehose")
endif()

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.


target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/logger.cpp"
)

ADD_OSQUERY_TEST_CORE(
  "${CMAKE_CURRENT_LIST_DIR}/tests/logger_tests.cpp"
)

if(NOT OSQUERY_BUILD_SDK_ONLY)
ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_logger_plugins
  "${CMAKE_CURRENT_LIST_DIR}/plugins/buffered.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/filesystem_logger.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_logger.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/stdout.cpp"
)

if(LINUX)
  target_sources(osquery_logger_plugins
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/syslog_logger.cpp"
  )
  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/syslog_logger_tests.cpp"
  )
elseif(WINDOWS)
  target_sources(osquery_logger_plugins
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/windows_event_log.cpp"
  )
endif()
endif()

# Keep the logger testing in the additional to test filesystem logging.
# There is a significant difference between the Glog-backed filesystem plugin
# and others, which use a Glog sink. They must be tested in tandem.
ADD_OSQUERY_TEST_ADDITIONAL(
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/filesystem_logger_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/buffered_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/tls_logger_tests.cpp"
)

ADD_OSQUERY_BENCHMARK(
  "${CMAKE_CURRENT_LIST_DIR}/benchmarks/logger_benchmarks.cpp"
)

if(NOT SKIP_KAFKA AND NOT WINDOWS AND NOT FREEBSD)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_logger_kafka_plugins
    "${CMAKE_CURRENT_LIST_DIR}/plugins/kafka_producer.cpp"
  )

  ADD_OSQUERY_LINK_ADDITIONAL("rdkafka")

  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/kafka_producer_tests.cpp"
  )
endif()

if(NOT SKIP_AWS)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_logger_aws_plugins
    "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_firehose.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_kinesis.cpp"
  )

  ADD_OSQUERY_TEST_ADDITIONAL(
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/aws_logger_tests.cpp"
  )

  if(WINDOWS)
    ADD_OSQUERY_LINK_CORE("UserEnv.lib")
    ADD_OSQUERY_LINK_CORE("bcrypt.lib")
    ADD_OSQUERY_LINK_CORE("wevtapi.lib")
  endif()

  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-kinesis")
  ADD_OSQUERY_LINK_ADDITIONAL("aws-cpp-sdk-firehose")
endif()

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

ADD_OSQUERY_LIBRARY(TRUE osquery_config
  "${CMAKE_CURRENT_LIST_DIR}/config.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/packs.cpp"
)

ADD_OSQUERY_LIBRARY(FALSE osquery_config_plugins
  "${CMAKE_CURRENT_LIST_DIR}/plugins/filesystem_config.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_config.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_config.h"
  "${CMAKE_CURRENT_LIST_DIR}/update.cpp"
)

ADD_OSQUERY_LIBRARY(TRUE osquery_config_parsers
  "${CMAKE_CURRENT_LIST_DIR}/parsers/decorators.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/decorators.h"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/events_parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/feature_vectors.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/feature_vectors.h"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/file_paths.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/kafka_topics.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/kafka_topics.h"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/logger.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/logger.h"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/options.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/prometheus_targets.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/prometheus_targets.h"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/views.cpp"
)

ADD_OSQUERY_LIBRARY(FALSE osquery_additional_config_parsers
  "${CMAKE_CURRENT_LIST_DIR}/additional_parsers/auto_constructed_tables.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/additional_parsers/auto_constructed_tables.h"
)

ADD_OSQUERY_TEST(TRUE
  "${CMAKE_CURRENT_LIST_DIR}/tests/config_tests.cpp"
)

# The packs tests will attempt to execute SQL, they must be additional
ADD_OSQUERY_TEST(FALSE
  "${CMAKE_CURRENT_LIST_DIR}/tests/packs_tests.cpp"
)

ADD_OSQUERY_TEST(FALSE
  "${CMAKE_CURRENT_LIST_DIR}/parsers/tests/file_paths_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/tests/views_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/tests/options_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/tests/decorators_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/parsers/tests/events_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/tls_config_tests.cpp"
)

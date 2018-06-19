#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

file(GLOB OSQUERY_NUMERIC_MONITORING "*.cpp")

ADD_OSQUERY_LIBRARY_CORE(
  OSQUERY_NUMERIC_MONITORING
  ${OSQUERY_NUMERIC_MONITORING}
)

file(GLOB OSQUERY_NUMERIC_MONITORING_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST_CORE(${OSQUERY_NUMERIC_MONITORING_TESTS})

set(OSQUERY_NUMERIC_MONITORING_PLUGINS
  "plugins/filesystem.cpp"
)

ADD_OSQUERY_LIBRARY_ADDITIONAL(
  OSQUERY_NUMERIC_MONITORING_PLUGINS
  ${OSQUERY_NUMERIC_MONITORING_PLUGINS}
)

set(OSQUERY_NUMERIC_MONITORING_PLUGIN_TESTS
  "numeric_monitoring/plugins/tests/filesystem_tests.cpp"
)

ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_NUMERIC_MONITORING_PLUGIN_TESTS})

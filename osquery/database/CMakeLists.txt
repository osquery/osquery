#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

ADD_OSQUERY_LIBRARY(TRUE osquery_database
  database.cpp
  tablecachedb.cpp
  plugins/ephemeral.cpp
)

# Optionally (but by default), add the RocksDB database plugin.
add_definitions(-DROCKSDB_LITE=1)

# Begin with just the SQLite database plugin.
set(OSQUERY_DATABASE_PLUGINS
  plugins/sqlite.cpp
  plugins/rocksdb.cpp
)

set(OSQUERY_DATABASE_PLUGIN_TESTS
  database/tests/plugin_tests.cpp
  database/plugins/tests/sqlite_tests.cpp
  database/plugins/tests/rocksdb_tests.cpp
)

# Plugins (which do not include the shim/ephemeral) are 'additional'.
ADD_OSQUERY_LIBRARY(FALSE osquery_database_plugins ${OSQUERY_DATABASE_PLUGINS})

# Non-plugin tests are core.
file(GLOB OSQUERY_DATABASE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_DATABASE_TESTS})

# Plugin tests are additional.
ADD_OSQUERY_TEST(FALSE ${OSQUERY_DATABASE_PLUGIN_TESTS})

file(GLOB OSQUERY_DATABASE_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_DATABASE_BENCHMARKS})

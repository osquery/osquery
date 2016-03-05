ADD_OSQUERY_LIBRARY(TRUE osquery_database
  database.cpp
  query.cpp

  # Add 'core' plugins that do not required additional libraries.
  plugins/ephemeral.cpp
)

# Begin with just the SQLite database plugin.
set(OSQUERY_DATABASE_PLUGINS
  plugins/sqlite.cpp
)

set(OSQUERY_DATABASE_PLUGIN_TESTS
  database/tests/plugin_tests.cpp
  database/plugins/tests/sqlite_tests.cpp
)

# Optionally (but by default), add the RocksDB database plugin.
if(ROCKSDB)
  if(ROCKSDB_LITE_FOUND)
    add_definitions(-DROCKSDB_LITE=1)
  endif()
  set(OSQUERY_DATABASE_PLUGINS ${OSQUERY_DATABASE_PLUGINS} plugins/rocksdb.cpp)
  set(OSQUERY_DATABASE_PLUGIN_TESTS ${OSQUERY_DATABASE_PLUGIN_TESTS} database/plugins/tests/rocksdb_tests.cpp)
else()
  add_definitions(-DSKIP_ROCKSDB)
endif()

# Plugins (which do not include the shim/ephemeral) are 'additional'.
ADD_OSQUERY_LIBRARY(FALSE osquery_database_plugins ${OSQUERY_DATABASE_PLUGINS})

# Non-plugin tests are core.
file(GLOB OSQUERY_DATABASE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_DATABASE_TESTS})

# Plugin tests are additional.
ADD_OSQUERY_TEST(FALSE ${OSQUERY_DATABASE_PLUGIN_TESTS})

file(GLOB OSQUERY_DATABASE_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_DATABASE_BENCHMARKS})

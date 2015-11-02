ADD_OSQUERY_LIBRARY(TRUE osquery_database
  database.cpp
)

# osquery_database_internal should be an 'additional' CORE=False lib
ADD_OSQUERY_LIBRARY(TRUE osquery_database_internal
  db_handle.cpp
  query.cpp
)

file(GLOB OSQUERY_DATABASE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_DATABASE_TESTS})

file(GLOB OSQUERY_DATABASE_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_DATABASE_BENCHMARKS})

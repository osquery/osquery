ADD_OSQUERY_LIBRARY(TRUE osquery_sql
  sql.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_sql_internal
  sqlite_util.cpp
  sqlite_math.cpp
  virtual_table.cpp
)

file(GLOB OSQUERY_SQL_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_SQL_TESTS})

file(GLOB OSQUERY_SQL_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_SQL_BENCHMARKS})

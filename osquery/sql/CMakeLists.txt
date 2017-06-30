ADD_OSQUERY_LIBRARY_CORE(osquery_sql
  sql.cpp
)

set(OSQUERY_SQL_INTERNAL
  "sqlite_util.cpp"
  "sqlite_math.cpp"
  "sqlite_hashing.cpp"
  "sqlite_encoding.cpp"
  "virtual_table.cpp"
)

if(NOT FREEBSD)
  list(APPEND OSQUERY_SQL_INTERNAL "sqlite_string.cpp")
endif()
if(NOT SKIP_CARVER)
  list(APPEND OSQUERY_SQL_INTERNAL "sqlite_operations.cpp")
endif()

ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_sql_internal
  ${OSQUERY_SQL_INTERNAL}
)

file(GLOB OSQUERY_SQL_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_SQL_TESTS})

file(GLOB OSQUERY_SQL_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_SQL_BENCHMARKS})

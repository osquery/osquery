ADD_OSQUERY_LIBRARY_CORE(osquery_sql
  sql.cpp
)

if(FREEBSD)
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_sql_internal
    sqlite_util.cpp
    sqlite_math.cpp
    sqlite_hashing.cpp
    virtual_table.cpp
  )
else()
  ADD_OSQUERY_LIBRARY_ADDITIONAL(osquery_sql_internal
    sqlite_util.cpp
    sqlite_math.cpp
    sqlite_string.cpp
    sqlite_hashing.cpp
    virtual_table.cpp
  )
endif()

file(GLOB OSQUERY_SQL_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST_ADDITIONAL(${OSQUERY_SQL_TESTS})

file(GLOB OSQUERY_SQL_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_SQL_BENCHMARKS})

ADD_OSQUERY_CORE_LIBRARY(osquery_database
  db_handle.cpp
  query.cpp
  results.cpp
)

ADD_OSQUERY_TEST(query_tests query_tests.cpp)
ADD_OSQUERY_TEST(db_handle_tests db_handle_tests.cpp)
ADD_OSQUERY_TEST(results_tests results_tests.cpp)

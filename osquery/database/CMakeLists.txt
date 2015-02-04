ADD_OSQUERY_LIBRARY(TRUE osquery_database
  db_handle.cpp
  query.cpp
  results.cpp
)

ADD_OSQUERY_TEST(TRUE query_tests query_tests.cpp)
ADD_OSQUERY_TEST(TRUE db_handle_tests db_handle_tests.cpp)
ADD_OSQUERY_TEST(TRUE results_tests results_tests.cpp)

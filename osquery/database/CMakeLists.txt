ADD_LIBRARY(osquery_database OBJECT
  ../database.h
  db_handle.h
  db_handle.cpp
  query.h
  query.cpp
  results.h
  results.cpp
)

SET_OSQUERY_COMPILE(osquery_database)

ADD_LIBRARY(osquery_testing_database
  $<TARGET_OBJECTS:osquery_core>
  $<TARGET_OBJECTS:osquery_database>
  $<TARGET_OBJECTS:osquery_sqlite>
  $<TARGET_OBJECTS:osquery_registry>
)

ADD_OSQUERY_TEST(query_tests query_tests.cpp
  osquery_testing_database)

ADD_OSQUERY_TEST(db_handle_tests db_handle_tests.cpp
  osquery_testing_database)

ADD_OSQUERY_TEST(results_tests results_tests.cpp
  osquery_testing_database)

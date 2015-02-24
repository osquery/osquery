ADD_OSQUERY_LIBRARY(TRUE osquery_sql
  sql.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_sql_internal
  sqlite_util.cpp
  virtual_table.cpp
)

ADD_OSQUERY_TEST(TRUE sql_test sql_tests.cpp)
ADD_OSQUERY_TEST(FALSE sqlite_util_tests sqlite_util_tests.cpp)
ADD_OSQUERY_TEST(FALSE virtual_table_tests virtual_table_tests.cpp)

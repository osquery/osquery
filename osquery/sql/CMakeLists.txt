ADD_OSQUERY_LIBRARY(TRUE osquery_sql
  sql.cpp
)

if(NOT OSQUERY_BUILD_SDK_ONLY)
  set(SQL_INTERNAL TRUE)
endif()

ADD_OSQUERY_LIBRARY(SQL_INTERNAL osquery_sql_internal
  sqlite_util.cpp
  virtual_table.cpp
)

ADD_OSQUERY_TEST(TRUE sql_test sql_tests.cpp)
ADD_OSQUERY_TEST(SQL_INTERNAL sqlite_util_tests sqlite_util_tests.cpp)
ADD_OSQUERY_TEST(SQL_INTERNAL virtual_table_tests virtual_table_tests.cpp)

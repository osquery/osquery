if(APPLE)
  set (OS_CORE_SOURCE
    darwin/conversions.cpp
  )
else()
  set (OS_CORE_SOURCE "")
endif()

ADD_OSQUERY_CORE_LIBRARY(osquery_core
  conversions.cpp
  init.cpp
  sql.cpp
  sqlite_util.cpp
  system.cpp
  test_util.cpp
  ${OS_CORE_SOURCE}
  tables.cpp
  virtual_table.cpp
  text.cpp
  flags.cpp
  hash.cpp
)

ADD_OSQUERY_TEST(status_test status_tests.cpp)
ADD_OSQUERY_TEST(sql_test sql_tests.cpp)
ADD_OSQUERY_TEST(sqlite_util_tests sqlite_util_tests.cpp)
ADD_OSQUERY_TEST(tables_tests tables_tests.cpp)
ADD_OSQUERY_TEST(test_util_tests test_util_tests.cpp)
ADD_OSQUERY_TEST(text_tests text_tests.cpp)
ADD_OSQUERY_TEST(conversions_tests conversions_tests.cpp)

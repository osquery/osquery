if(APPLE)
  set (OS_CORE_SOURCE darwin/test_util.cpp darwin/test_util.h)
else()
  set (OS_CORE_SOURCE "")
endif()

ADD_OSQUERY_LIBRARY(osquery_core
  init_osquery.cpp
  sql.cpp
  sqlite_util.cpp
  system.cpp
  test_util.cpp
  ${OS_CORE_SOURCE}
  tables.cpp
  text.cpp
)

ADD_OSQUERY_TEST(status_test status_tests.cpp)
ADD_OSQUERY_TEST(sql_test sql_tests.cpp)
ADD_OSQUERY_TEST(sqlite_util_tests sqlite_util_tests.cpp)
ADD_OSQUERY_TEST(test_util_tests test_util_tests.cpp)
ADD_OSQUERY_TEST(text_tests text_tests.cpp)
ADD_OSQUERY_TEST(conversions_tests conversions_tests.cpp)

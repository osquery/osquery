if(APPLE)
  set (OS_CORE_SOURCE "darwin/test_util.cpp")
else()
  set (OS_CORE_SOURCE "")
endif()

ADD_LIBRARY(osquery_core OBJECT
  init_osquery.cpp
  sqlite_util.cpp
  system.cpp
  test_util.cpp
  ${OS_CORE_SOURCE}
  text.cpp
)

SET_OSQUERY_COMPILE(osquery_core)

ADD_OSQUERY_TEST(status_test status_tests.cpp "")

ADD_LIBRARY(osquery_testing_core 
  $<TARGET_OBJECTS:osquery_core>
  $<TARGET_OBJECTS:osquery_database>
  $<TARGET_OBJECTS:osquery_sqlite>
  $<TARGET_OBJECTS:osquery_registry>
)

ADD_OSQUERY_TEST(sqlite_util_tests sqlite_util_tests.cpp 
  osquery_testing_core)

ADD_OSQUERY_TEST(test_util_tests test_util_tests.cpp 
  osquery_testing_core)

ADD_OSQUERY_TEST(text_tests text_tests.cpp 
  osquery_testing_core)

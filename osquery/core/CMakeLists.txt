if(APPLE)
  set (OS_CORE_SOURCE
    darwin/conversions.cpp
  )
else()
  set (OS_CORE_SOURCE "")
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_core
  conversions.cpp
  init.cpp
  system.cpp
  ${OS_CORE_SOURCE}
  tables.cpp
  text.cpp
  flags.cpp
  hash.cpp
  watcher.cpp
)

ADD_OSQUERY_TEST(TRUE flags_tests flags_tests.cpp)
ADD_OSQUERY_TEST(TRUE hash_test hash_tests.cpp)
ADD_OSQUERY_TEST(TRUE status_test status_tests.cpp)
ADD_OSQUERY_TEST(TRUE tables_tests tables_tests.cpp)
ADD_OSQUERY_TEST(TRUE text_tests text_tests.cpp)
ADD_OSQUERY_TEST(TRUE conversions_tests conversions_tests.cpp)

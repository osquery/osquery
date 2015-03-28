ADD_OSQUERY_LIBRARY(TRUE osquery_dispatcher
  dispatcher.cpp
  scheduler.cpp
)

if(APPLE)
  ADD_OSQUERY_TEST(TRUE dispatcher_tests dispatcher_tests.cpp)
endif()

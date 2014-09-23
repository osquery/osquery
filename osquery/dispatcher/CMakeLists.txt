ADD_LIBRARY(osquery_dispatcher OBJECT
  dispatcher.cpp
)
SET_OSQUERY_COMPILE(osquery_dispatcher)

if(APPLE)
  ADD_OSQUERY_TEST(dispatcher_tests dispatcher_tests.cpp)
endif()

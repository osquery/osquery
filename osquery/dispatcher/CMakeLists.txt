ADD_OSQUERY_LIBRARY(osquery_dispatcher
  dispatcher.cpp
)

if(APPLE)
  ADD_OSQUERY_TEST(dispatcher_tests dispatcher_tests.cpp)
endif()

ADD_LIBRARY(osquery_dispatcher OBJECT
  dispatcher.cpp
  events.cpp
)
SET_OSQUERY_COMPILE(osquery_dispatcher)

ADD_LIBRARY(osquery_dispatcher_testing
  $<TARGET_OBJECTS:osquery_dispatcher>
)

ADD_OSQUERY_TEST(dispatcher_tests dispatcher_tests.cpp osquery_dispatcher_testing)
ADD_OSQUERY_TEST(events_tests events_tests.cpp osquery_dispatcher_testing)

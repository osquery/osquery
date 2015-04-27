ADD_OSQUERY_LIBRARY(TRUE osquery_dispatcher
  dispatcher.cpp
  scheduler.cpp
)

file(GLOB OSQUERY_DISPATCHER_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_DISPATCHER_TESTS})

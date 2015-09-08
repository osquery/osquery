ADD_OSQUERY_LIBRARY(TRUE osquery_dispatcher
  dispatcher.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_dispatcher_runners
  scheduler.cpp
  distributed.cpp
)

# Note: if there are ever scheduler tests this needs to set the
# test files manually.
file(GLOB OSQUERY_DISPATCHER_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_DISPATCHER_TESTS})

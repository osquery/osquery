ADD_OSQUERY_LIBRARY(TRUE osquery_dispatcher
  dispatcher.cpp
)

ADD_OSQUERY_TEST(TRUE
  dispatcher/tests/dispatcher_tests.cpp
)

# The following dispatcher ("runner") implementations are additional.
SET(OSQUERY_DISPATCHER_RUNNERS
  scheduler.cpp
  distributed.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_dispatcher_runners
  ${OSQUERY_DISPATCHER_RUNNERS}
)


ADD_OSQUERY_TEST(FALSE
  dispatcher/tests/scheduler_tests.cpp
)

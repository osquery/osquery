ADD_OSQUERY_LIBRARY(TRUE osquery_dispatcher
  dispatcher.cpp
)

ADD_OSQUERY_TEST(TRUE
  dispatcher/tests/dispatcher_tests.cpp
)

# The following dispatcher ("runner") implementations are additional.
SET(osquery_dispatcher_runners_list
  scheduler.cpp
  distributed.cpp
)
if(NOT WINDOWS)
  list(APPEND osquery_dispatcher_runners_list bro.cpp)
endif()

ADD_OSQUERY_LIBRARY(FALSE osquery_dispatcher_runners
  ${osquery_dispatcher_runners_list}
)


ADD_OSQUERY_TEST(FALSE
  dispatcher/tests/scheduler_tests.cpp
)

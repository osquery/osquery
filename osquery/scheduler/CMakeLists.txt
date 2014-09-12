ADD_LIBRARY(osquery_scheduler OBJECT
  scheduler.cpp
)

SET_OSQUERY_COMPILE(osquery_scheduler)

ADD_OSQUERY_TEST(scheduler_tests scheduler_tests.cpp "")

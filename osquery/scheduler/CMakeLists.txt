ADD_OSQUERY_LIBRARY(osquery_scheduler
  scheduler.cpp
)

ADD_OSQUERY_TEST(scheduler_tests scheduler_tests.cpp)

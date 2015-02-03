ADD_OSQUERY_LIBRARY(TRUE osquery_scheduler
  scheduler.cpp
)

ADD_OSQUERY_TEST(TRUE scheduler_tests scheduler_tests.cpp)

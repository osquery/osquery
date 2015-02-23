ADD_OSQUERY_LIBRARY(TRUE osquery_distributed distributed.cpp)

ADD_OSQUERY_TEST(FALSE distributed_tests distributed_tests.cpp)

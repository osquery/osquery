ADD_OSQUERY_LIBRARY(TRUE osquery_registry
  registry.cpp
)

ADD_OSQUERY_TEST(TRUE registry_tests registry_tests.cpp)

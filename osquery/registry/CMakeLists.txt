ADD_LIBRARY(osquery_registry OBJECT
  registry.cpp
)

SET_OSQUERY_COMPILE(osquery_registry)

ADD_OSQUERY_TEST(registry_tests registry_tests.cpp "")

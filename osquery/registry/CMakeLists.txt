ADD_OSQUERY_CORE_LIBRARY(osquery_registry
  registry.cpp
)

ADD_OSQUERY_TEST(core_registry_tests registry_tests.cpp)

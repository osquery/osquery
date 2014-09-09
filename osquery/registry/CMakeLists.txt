ADD_LIBRARY(osquery_registry OBJECT
  ../registry.h
  init_registry.h
  registry.h
  registry.cpp
  registry_template.h
  singleton.h
)

SET_OSQUERY_COMPILE(osquery_registry)

ADD_OSQUERY_TEST(registry_tests registry_tests.cpp "")

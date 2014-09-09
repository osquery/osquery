ADD_LIBRARY(osquery_config OBJECT
  config.cpp
  plugins/filesystem.cpp
)

SET_OSQUERY_COMPILE(osquery_config)

ADD_LIBRARY(osquery_testing_config
  $<TARGET_OBJECTS:osquery_core>
  $<TARGET_OBJECTS:osquery_sqlite>
  $<TARGET_OBJECTS:osquery_registry>
  $<TARGET_OBJECTS:osquery_config>
)

ADD_OSQUERY_TEST(config_tests config_tests.cpp 
  osquery_testing_config)

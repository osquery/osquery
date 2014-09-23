ADD_LIBRARY(osquery_config OBJECT
  config.cpp
  plugins/filesystem.cpp
)

SET_OSQUERY_COMPILE(osquery_config)

ADD_OSQUERY_TEST(config_tests config_tests.cpp)

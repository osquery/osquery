ADD_OSQUERY_CORE_LIBRARY(osquery_config
  config.cpp
  plugins/filesystem.cpp
)

ADD_OSQUERY_TEST(config_tests config_tests.cpp)

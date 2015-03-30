ADD_OSQUERY_LIBRARY(TRUE osquery_config
  config.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_config_plugins
  update.cpp
  plugins/filesystem.cpp
)

ADD_OSQUERY_TEST(FALSE config_tests config_tests.cpp)

ADD_OSQUERY_LIBRARY(TRUE osquery_config
  config.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_config_plugins
  update.cpp
  plugins/filesystem.cpp
  plugins/http.cpp
)

file(GLOB OSQUERY_CONFIG_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_CONFIG_TESTS})

file(GLOB OSQUERY_CONFIG_PLUGIN_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_CONFIG_PLUGIN_TESTS})

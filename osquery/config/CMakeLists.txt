ADD_OSQUERY_LIBRARY(TRUE osquery_config
  config.cpp
)

set(OSQUERY_CONFIG_PLUGINS
  plugins/filesystem.cpp
  plugins/tls.cpp
  update.cpp
)

file(GLOB OSQUERY_CONFIG_PARSERS "parsers/*.cpp")

ADD_OSQUERY_LIBRARY(FALSE osquery_config_plugins
  ${OSQUERY_CONFIG_PLUGINS}
)

ADD_OSQUERY_LIBRARY(FALSE osquery_config_parsers
  ${OSQUERY_CONFIG_PARSERS}
)

file(GLOB OSQUERY_CONFIG_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_CONFIG_TESTS})

file(GLOB OSQUERY_CONFIG_PLUGIN_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_CONFIG_PLUGIN_TESTS})

ADD_OSQUERY_LIBRARY(osquery_config
  config.cpp
  plugins/filesystem.cpp
  plugins/glog.cpp
  plugins/zookeeper.cpp  
  plugins/rdkafka.cpp
)

ADD_OSQUERY_TEST(config_tests config_tests.cpp)

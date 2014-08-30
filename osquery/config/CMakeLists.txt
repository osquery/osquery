ADD_LIBRARY(osquery_config
  config.cpp
  plugins/filesystem.cpp
)
TARGET_LINK_LIBRARIES(osquery_config boost_filesystem)
TARGET_LINK_LIBRARIES(osquery_config boost_system)
TARGET_LINK_LIBRARIES(osquery_config boost_thread-mt)
TARGET_LINK_LIBRARIES(osquery_config gflags)
TARGET_LINK_LIBRARIES(osquery_config glog)
TARGET_LINK_LIBRARIES(osquery_config "-Wl,-all_load")
SET_TARGET_PROPERTIES(osquery_config PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

ADD_EXECUTABLE(config_tests config_tests.cpp)
TARGET_LINK_LIBRARIES(config_tests gtest)
TARGET_LINK_LIBRARIES(config_tests osquery_config)
TARGET_LINK_LIBRARIES(config_tests osquery_core)
TARGET_LINK_LIBRARIES(config_tests osquery_sqlite)
SET_TARGET_PROPERTIES(config_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

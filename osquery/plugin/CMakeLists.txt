ADD_LIBRARY(foobar_plugin SHARED
  included/foobar.cpp
)

ADD_LIBRARY(osquery_plugin
  registry.cpp
)
TARGET_LINK_LIBRARIES(osquery_plugin gflags)
TARGET_LINK_LIBRARIES(osquery_plugin glog)
TARGET_LINK_LIBRARIES(osquery_plugin osquery_filesystem)
SET_TARGET_PROPERTIES(osquery_plugin PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})

ADD_EXECUTABLE(registry_tests registry_tests.cpp)
TARGET_LINK_LIBRARIES(registry_tests gtest)
TARGET_LINK_LIBRARIES(registry_tests osquery_plugin)
SET_TARGET_PROPERTIES(registry_tests PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
ADD_TEST(registry_tests registry_tests)

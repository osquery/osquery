ADD_EXECUTABLE(flag_test flag_test.cpp)
TARGET_LINK_LIBRARIES(flag_test gflags glog)

ADD_EXECUTABLE(registry_test registry_test.cpp)
TARGET_LINK_LIBRARIES(registry_test gflags glog osquery_static)

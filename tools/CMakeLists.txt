ADD_EXECUTABLE(flag_test flag_test.cpp)
TARGET_LINK_LIBRARIES(flag_test gflags glog)
SET_TARGET_PROPERTIES(flag_test PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
ADD_TEST(flag_test flag_test --config_retriever="foo" --config_path="bar" --log_receiver="baz" --log_path="boo")

ADD_EXECUTABLE(registry_test registry_test.cpp)
TARGET_LINK_LIBRARIES(registry_test osquery_static)
SET_TARGET_PROPERTIES(registry_test PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
ADD_TEST(registry_test registry_test)

ADD_EXECUTABLE(run run.cpp)
TARGET_LINK_LIBRARIES(run osquery_static)
SET_TARGET_PROPERTIES(run PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})


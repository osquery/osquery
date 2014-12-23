#ADD_EXECUTABLE(flag_test flag_test.cpp)
#TARGET_LINK_LIBRARIES(flag_test gflags glog)
#SET_TARGET_PROPERTIES(flag_test PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})

ADD_OSQUERY_TEST(flag_test flag_test.cpp)

#ADD_EXECUTABLE(registry_test registry_test.cpp)
#TARGET_LINK_LIBRARIES(registry_test osquery_shared)
#SET_TARGET_PROPERTIES(registry_test PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
#ADD_TEST(registry_test registry_test)

ADD_OSQUERY_TEST(registry_test registry_test.cpp)

ADD_EXECUTABLE(run run.cpp)
TARGET_LINK_LIBRARIES(run libosquery)
SET_TARGET_PROPERTIES(run PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
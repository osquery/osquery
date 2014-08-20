ADD_EXECUTABLE(flag_test flag_test.cpp)
TARGET_LINK_LIBRARIES(flag_test gflags glog)
SET_TARGET_PROPERTIES(flag_test PROPERTIES OUTPUT_NAME flag_test)

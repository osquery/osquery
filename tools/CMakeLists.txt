ADD_EXECUTABLE(flag_test flag_test.cpp)
TARGET_LINK_LIBRARIES(flag_test gflags glog)
SET_TARGET_PROPERTIES(flag_test PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

ADD_EXECUTABLE(registry_test registry_test.cpp)
TARGET_LINK_LIBRARIES(registry_test gflags glog osquery_static)
SET_TARGET_PROPERTIES(registry_test PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

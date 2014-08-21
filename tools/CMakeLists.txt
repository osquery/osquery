ADD_EXECUTABLE(flag_test flag_test.cpp)
TARGET_LINK_LIBRARIES(flag_test gflags glog)

ADD_EXECUTABLE(registry_test registry_test.cpp)
TARGET_LINK_LIBRARIES(registry_test gflags glog osquery_static)

ADD_EXECUTABLE(hostname hostname.cpp)
TARGET_LINK_LIBRARIES(hostname osquery_static)

ADD_EXECUTABLE(time time.cpp)
TARGET_LINK_LIBRARIES(time osquery_static)

ADD_EXECUTABLE(aggregate_query aggregate_query.cpp)
TARGET_LINK_LIBRARIES(aggregate_query osquery_static)

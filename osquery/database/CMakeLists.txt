ADD_LIBRARY(osquery_database
  db_handle.cpp
  query.cpp
  results.cpp
)
ADD_DEPENDENCIES(osquery_database librocksdb)
TARGET_LINK_LIBRARIES(osquery_database boost_system)
TARGET_LINK_LIBRARIES(osquery_database boost_thread-mt)
TARGET_LINK_LIBRARIES(osquery_database bz2)
TARGET_LINK_LIBRARIES(osquery_database glog)
TARGET_LINK_LIBRARIES(osquery_database gtest)
TARGET_LINK_LIBRARIES(osquery_database rocksdb)
TARGET_LINK_LIBRARIES(osquery_database snappy)
TARGET_LINK_LIBRARIES(osquery_database z)
TARGET_LINK_LIBRARIES(osquery_database osquery_config)
SET_TARGET_PROPERTIES(osquery_database PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")

ADD_EXECUTABLE(query_tests query_tests.cpp)
ADD_DEPENDENCIES(query_tests librocksdb)
TARGET_LINK_LIBRARIES(query_tests gtest)
TARGET_LINK_LIBRARIES(query_tests osquery_core)
TARGET_LINK_LIBRARIES(query_tests osquery_database)
SET_TARGET_PROPERTIES(query_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
ADD_TEST(query_tests query_tests)

ADD_EXECUTABLE(db_handle_tests db_handle_tests.cpp)
ADD_DEPENDENCIES(db_handle_tests librocksdb)
TARGET_LINK_LIBRARIES(db_handle_tests gtest)
TARGET_LINK_LIBRARIES(db_handle_tests osquery_database)
SET_TARGET_PROPERTIES(db_handle_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
ADD_TEST(db_handle_tests db_handle_tests)

ADD_EXECUTABLE(results_tests results_tests)
ADD_DEPENDENCIES(results_tests librocksdb)
TARGET_LINK_LIBRARIES(results_tests gtest)
TARGET_LINK_LIBRARIES(results_tests osquery_core)
TARGET_LINK_LIBRARIES(results_tests osquery_database)
SET_TARGET_PROPERTIES(results_tests PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
ADD_TEST(results_tests results_tests)

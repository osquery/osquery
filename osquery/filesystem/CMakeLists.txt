if(APPLE)
ADD_LIBRARY(osquery_filesystem_osx
  plist.mm
)
TARGET_LINK_LIBRARIES(osquery_filesystem_osx boost_program_options)
TARGET_LINK_LIBRARIES(osquery_filesystem_osx glog)
TARGET_LINK_LIBRARIES(osquery_filesystem_osx "-fobjc-arc -fobjc-link-runtime -framework Foundation")
endif()

ADD_LIBRARY(osquery_filesystem
  filesystem.cpp
)
TARGET_LINK_LIBRARIES(osquery_filesystem boost_filesystem)
TARGET_LINK_LIBRARIES(osquery_filesystem boost_system)
TARGET_LINK_LIBRARIES(osquery_filesystem boost_program_options)
TARGET_LINK_LIBRARIES(osquery_filesystem boost_thread-mt)
TARGET_LINK_LIBRARIES(osquery_filesystem gflags)
TARGET_LINK_LIBRARIES(osquery_filesystem glog)
if(APPLE)
TARGET_LINK_LIBRARIES(osquery_filesystem osquery_filesystem_osx)
endif()

ADD_EXECUTABLE(filesystem_tests filesystem_tests.cpp)
TARGET_LINK_LIBRARIES(filesystem_tests gtest)
TARGET_LINK_LIBRARIES(filesystem_tests osquery_filesystem)

if(APPLE)
ADD_EXECUTABLE(plist_tests plist_tests.mm)
TARGET_LINK_LIBRARIES(plist_tests glog)
TARGET_LINK_LIBRARIES(plist_tests gtest)
TARGET_LINK_LIBRARIES(plist_tests osquery_core)
TARGET_LINK_LIBRARIES(plist_tests osquery_filesystem)
endif()

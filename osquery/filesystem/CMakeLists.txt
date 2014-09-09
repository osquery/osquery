set(OSQUERY_FILESYSTEM_TARGETS "")

if(APPLE)
  ADD_LIBRARY(osquery_filesystem_objc OBJECT
    darwin/plist.mm
  )

  ADD_OSQUERY_LINK("-framework Foundation")
  SET_OSQUERY_COMPILE(osquery_filesystem_objc "-x objective-c++ -fobjc-arc")

  list(APPEND OSQUERY_FILESYSTEM_TARGETS $<TARGET_OBJECTS:osquery_filesystem_objc>)
endif()

# Additional targets for OS-specific filesystem capabilities
ADD_OSQUERY_LIB("${OSQUERY_FILESYSTEM_TARGETS}")

ADD_LIBRARY(osquery_filesystem OBJECT
  ../filesystem.h
  filesystem.cpp
)

SET_OSQUERY_COMPILE(osquery_filesystem)

ADD_LIBRARY(osquery_testing_filesystem
  $<TARGET_OBJECTS:osquery_core>
  $<TARGET_OBJECTS:osquery_filesystem>
  ${OSQUERY_FILESYSTEM_TARGETS}
)

ADD_OSQUERY_TEST(filesystem_tests filesystem_tests.cpp
  osquery_testing_filesystem)

if(APPLE)
  ADD_OSQUERY_TEST(plist_tests darwin/plist_tests.cpp
    osquery_testing_filesystem)

  ADD_OSQUERY_TEST(plist_benchmark darwin/plist_benchmark.cpp
    osquery_testing_filesystem)
endif()

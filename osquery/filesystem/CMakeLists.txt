if(APPLE)
  ADD_OSQUERY_OBJCXX_LIBRARY(TRUE osquery_filesystem_objc
    darwin/plist.mm
  )

  ADD_OSQUERY_LINK(TRUE "-framework Foundation")
elseif(LINUX)
  ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem_linux
    linux/mem.cpp
    linux/proc.cpp
  )
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem
  filesystem.cpp
)

ADD_OSQUERY_TEST(TRUE filesystem_tests filesystem_tests.cpp)
if(APPLE)
  ADD_OSQUERY_TEST(TRUE plist_tests darwin/plist_tests.cpp)
  ADD_OSQUERY_TEST(TRUE plist_benchmark darwin/plist_benchmark.cpp)
endif()

if(APPLE)
  ADD_OSQUERY_CORE_OBJCXX_LIBRARY(osquery_filesystem_objc
    darwin/plist.mm
  )

  ADD_OSQUERY_CORE_LINK("-framework Foundation")
elseif(UBUNTU OR CENTOS)
  ADD_OSQUERY_CORE_LIBRARY(osquery_filesystem_linux
    linux/mem.cpp
    linux/proc.cpp
  )
endif()

ADD_OSQUERY_CORE_LIBRARY(osquery_filesystem
  filesystem.cpp
)

ADD_OSQUERY_TEST(filesystem_tests filesystem_tests.cpp)
if(APPLE)
  ADD_OSQUERY_TEST(plist_tests darwin/plist_tests.cpp)
  ADD_OSQUERY_TEST(plist_benchmark darwin/plist_benchmark.cpp)
endif()

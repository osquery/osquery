if(APPLE)
  ADD_OSQUERY_OBJCXX_LIBRARY(TRUE osquery_filesystem_objc
    darwin/plist.mm
  )

  ADD_OSQUERY_LINK(TRUE "-framework Foundation")
elseif(FREEBSD)
elseif(LINUX)
  ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem_linux
    linux/mem.cpp
    linux/proc.cpp
  )
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem
  filesystem.cpp
)

file(GLOB OSQUERY_FILESYSTEM_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_FILESYSTEM_TESTS})

if(APPLE)
  file(GLOB OSQUERY_DARWIN_FILESYSTEM_TESTS "darwin/tests/*.cpp")
  ADD_OSQUERY_TEST(TRUE ${OSQUERY_DARWIN_FILESYSTEM_TESTS})
endif()

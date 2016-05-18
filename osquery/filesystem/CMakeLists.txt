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

if(WIN32)
  set(PROCESS_FAMILY "windows")
else()
  set(PROCESS_FAMILY "posix")
endif()
file(GLOB OS_FILEOPS_SOURCE "${PROCESS_FAMILY}/*.cpp")

ADD_OSQUERY_LIBRARY(TRUE osquery_filesystem
  filesystem.cpp
  ${OS_FILEOPS_SOURCE}
)

file(GLOB OSQUERY_FILESYSTEM_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_FILESYSTEM_TESTS})

if(APPLE)
  file(GLOB OSQUERY_DARWIN_FILESYSTEM_TESTS "darwin/tests/*.cpp")
  ADD_OSQUERY_TEST(TRUE ${OSQUERY_DARWIN_FILESYSTEM_TESTS})

  file(GLOB OSQUERY_DARWIN_FILESYSTEM_BENCHMARKS "darwin/benchmarks/*.cpp")
  ADD_OSQUERY_BENCHMARK(${OSQUERY_DARWIN_FILESYSTEM_BENCHMARKS})
elseif(WIN32)
  file(GLOB OSQUERY_WINDOWS_FILEOPS_TESTS "windows/tests/*.cpp")
  ADD_OSQUERY_TEST(TRUE ${OSQUERY_WINDOWS_FILEOPS_TESTS})
endif()

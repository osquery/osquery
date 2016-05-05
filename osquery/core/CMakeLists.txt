if(WIN32)
  set (OS_CORE_SOURCE
    windows/process.cpp
    windows/process_ops.cpp  
  )
else()
  set (OS_CORE_SOURCE
    posix/process.cpp
    posix/process_ops.cpp
  )
endif()

if(APPLE)
  set (OS_CORE_SOURCE
    ${OS_CORE_SOURCE}
    darwin/conversions.cpp
  )
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_core
  conversions.cpp
  init.cpp
  system.cpp
  ${OS_CORE_SOURCE}
  tables.cpp
  flags.cpp
  hash.cpp
  watcher.cpp
  process_shared.cpp
)

file(GLOB OSQUERY_CORE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_CORE_TESTS})

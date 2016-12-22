file(GLOB OS_CORE_SOURCE "${PROCESS_FAMILY}/*.cpp")
file(GLOB OS_CORE_TESTS_SOURCE "tests/${PROCESS_FAMILY}/*.cpp")

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
  watcher.cpp
  process_shared.cpp
)

file(GLOB OSQUERY_CORE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_CORE_TESTS} ${OS_CORE_TESTS_SOURCE})

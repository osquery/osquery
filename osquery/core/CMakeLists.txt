if(APPLE)
  set (OS_CORE_SOURCE
    darwin/conversions.cpp
  )
else()
  set (OS_CORE_SOURCE "")
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
)

file(GLOB OSQUERY_CORE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_CORE_TESTS})

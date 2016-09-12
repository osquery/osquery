ADD_OSQUERY_LIBRARY(TRUE osquery_distributed
  distributed.cpp
)

if(NOT WINDOWS)
  ADD_OSQUERY_LIBRARY(FALSE osquery_distributed_plugins
    plugins/tls.cpp
  )
endif()

if(NOT WINDOWS)
  file(GLOB OSQUERY_DISTRIBUTED_TESTS "tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_DISTRIBUTED_TESTS})
endif()

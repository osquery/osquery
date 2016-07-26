ADD_OSQUERY_LIBRARY(TRUE osquery_distributed
  distributed.cpp
)

if(NOT WIN32)
  ADD_OSQUERY_LIBRARY(FALSE osquery_distributed_plugins
    plugins/tls.cpp
  )
endif()

file(GLOB OSQUERY_DISTRIBUTED_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_DISTRIBUTED_TESTS})

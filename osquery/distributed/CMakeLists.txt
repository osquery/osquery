ADD_OSQUERY_LIBRARY(TRUE osquery_ondemand
  ondemand.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_distributed
  distributed.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_distributed_plugins
  plugins/tls.cpp
)

file(GLOB OSQUERY_DISTRIBUTED_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_DISTRIBUTED_TESTS})

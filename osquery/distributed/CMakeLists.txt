ADD_OSQUERY_LIBRARY(TRUE osquery_distributed
  distributed.cpp
)

SET(OSQUERY_DISTRIBUTED_PLUGINS
  plugins/tls_distributed.cpp
)

if(NOT WINDOWS)
  LIST(APPEND OSQUERY_DISTRIBUTED_PLUGINS "plugins/bro_distributed.cpp")
endif()

ADD_OSQUERY_LIBRARY(FALSE osquery_distributed_plugins ${OSQUERY_DISTRIBUTED_PLUGINS})

file(GLOB OSQUERY_DISTRIBUTED_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_DISTRIBUTED_TESTS})

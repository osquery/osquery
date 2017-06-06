set(OSQUERY_REMOTE
  "enroll/enroll.cpp"
  "serializers/json.cpp"
  "transports/tls.cpp"
  "remote.cpp"
)

if(NOT WINDOWS)
    LIST(APPEND OSQUERY_REMOTE "bro/BrokerManager.cpp")
    LIST(APPEND OSQUERY_REMOTE "bro/QueryManager.cpp")
    LIST(APPEND OSQUERY_REMOTE "bro/utils.cpp")
endif()

ADD_OSQUERY_LIBRARY(FALSE osquery_remote ${OSQUERY_REMOTE})

ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
  enroll/plugins/tls_enroll.cpp
)

file(GLOB OSQUERY_ENROLLMENT_PLUGIN_TESTS "enrollment/plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_ENROLLMENT_PLUGIN_TESTS})

file(GLOB OSQUERY_REMOTE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_TESTS})

file(GLOB OSQUERY_REMOTE_COMPONENT_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_COMPONENT_TESTS})

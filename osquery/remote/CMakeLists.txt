ADD_OSQUERY_LIBRARY(FALSE osquery_remote
  enroll/enroll.cpp
  serializers/json.cpp
  transports/tls.cpp
)

if(NOT OSQUERY_BUILD_RELEASE)
  ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
    enroll/plugins/tls.cpp
  )
endif()

file(GLOB OSQUERY_ENROLLMENT_PLUGIN_TESTS "enrollment/plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_ENROLLMENT_PLUGIN_TESTS})

file(GLOB OSQUERY_REMOTE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_TESTS})

file(GLOB OSQUERY_REMOTE_COMPONENT_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_COMPONENT_TESTS})

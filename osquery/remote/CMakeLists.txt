ADD_OSQUERY_LIBRARY(FALSE osquery_remote
  enrollment/enrollment.cpp
  serializers/json.cpp
  transports/http.cpp
)

if(NOT OSQUERY_BUILD_RELEASE)
  ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
    enrollment/plugins/http.cpp
  )
endif()

file(GLOB OSQUERY_ENROLLMENT_PLUGIN_TESTS "enrollment/plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_ENROLLMENT_PLUGIN_TESTS})

file(GLOB OSQUERY_REMOTE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_TESTS})

file(GLOB OSQUERY_REMOTE_COMPONENT_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_COMPONENT_TESTS})

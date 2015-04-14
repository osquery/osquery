ADD_OSQUERY_LIBRARY(TRUE osquery_requests
  requests.h
  transports/http.h
  transports/http.cpp
  serializers/json.h
  serializers/json.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment
  enrollment/plugins/http_enrollment.cpp
)

ADD_OSQUERY_TEST(FALSE requests_tests requests_tests.cpp)
ADD_OSQUERY_TEST(FALSE json_tests serializers/json_tests.cpp)
ADD_OSQUERY_TEST(FALSE http_tests transports/http_tests.cpp)
ADD_OSQUERY_TEST(FALSE enrollment_tests enrollment/enrollment_tests.cpp)
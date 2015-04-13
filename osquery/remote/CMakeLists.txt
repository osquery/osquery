ADD_OSQUERY_LIBRARY(TRUE osquery_requests
  requests.h
  transports/http.h
  transports/http.cpp
  serializers/json.h
  serializers/json.cpp
)

ADD_OSQUERY_TEST(TRUE requests_tests requests_tests.cpp)
ADD_OSQUERY_TEST(TRUE json_tests serializers/json_tests.cpp)
ADD_OSQUERY_TEST(TRUE http_tests transports/http_tests.cpp)

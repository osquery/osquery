#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

ADD_OSQUERY_LIBRARY(FALSE osquery_remote
  "${CMAKE_CURRENT_LIST_DIR}/enroll/enroll.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/serializers/json.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/serializers/json.h"
  "${CMAKE_CURRENT_LIST_DIR}/transports/tls.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/transports/tls.h"
  "${CMAKE_CURRENT_LIST_DIR}/http/http_client.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/remote.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/uri.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/uri.h"
  "${CMAKE_CURRENT_LIST_DIR}/utility.h"
)

ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
  "${CMAKE_CURRENT_LIST_DIR}/enroll/plugins/tls_enroll.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/enroll/plugins/tls_enroll.h"
)

ADD_OSQUERY_TEST(FALSE
  "${CMAKE_CURRENT_LIST_DIR}/enroll/plugins/tests/tls_enroll_tests.cpp"
)

ADD_OSQUERY_TEST(FALSE
  "${CMAKE_CURRENT_LIST_DIR}/tests/requests_tests.cpp"
)

ADD_OSQUERY_TEST(FALSE 
  "${CMAKE_CURRENT_LIST_DIR}/enroll/tests/enroll_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/serializers/tests/json_serializers_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/transports/tests/tls_transports_tests.cpp"
)

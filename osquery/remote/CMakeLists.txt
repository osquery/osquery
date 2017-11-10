#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

<<<<<<< HEAD
set(OSQUERY_REMOTE
  "enroll/enroll.cpp"
  "serializers/json.cpp"
  "transports/tls.cpp"
  "http/http_client.cpp"
  "remote.cpp"
)

if(NOT SKIP_BRO)
  LIST(APPEND OSQUERY_REMOTE "bro/broker_manager.cpp")
  LIST(APPEND OSQUERY_REMOTE "bro/query_manager.cpp")
  LIST(APPEND OSQUERY_REMOTE "bro/bro_utils.cpp")
endif()

ADD_OSQUERY_LIBRARY(FALSE osquery_remote ${OSQUERY_REMOTE})

ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
  enroll/plugins/tls_enroll.cpp
)

file(GLOB OSQUERY_ENROLLMENT_PLUGIN_TESTS "enroll/plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_ENROLLMENT_PLUGIN_TESTS})

file(GLOB OSQUERY_REMOTE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_TESTS})

SET(GLOB OSQUERY_REMOTE_COMPONENT_TESTS)

if(NOT SKIP_BRO)
  file(GLOB OSQUERY_REMOTE_BRO_TESTS "bro/tests/*.cpp")
  LIST(APPEND OSQUERY_REMOTE_COMPONENT_TESTS ${OSQUERY_REMOTE_BRO_TESTS})
endif()

file(GLOB OSQUERY_REMOTE_ENROLL_TESTS "enroll/tests/*.cpp")
LIST(APPEND OSQUERY_REMOTE_COMPONENT_TESTS ${OSQUERY_REMOTE_ENROLL_TESTS})

file(GLOB OSQUERY_REMOTE_SERIALIZERS_TESTS "serializers/tests/*.cpp")
LIST(APPEND OSQUERY_REMOTE_COMPONENT_TESTS ${OSQUERY_REMOTE_SERIALIZERS_TESTS})

file(GLOB OSQUERY_REMOTE_TRANSPORTS_TESTS "transports/tests/*.cpp")
LIST(APPEND OSQUERY_REMOTE_COMPONENT_TESTS ${OSQUERY_REMOTE_TRANSPORTS_TESTS})

ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_COMPONENT_TESTS})

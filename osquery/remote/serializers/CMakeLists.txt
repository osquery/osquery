# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRemoteSerializersMain)

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryRemoteserializersjsontestsTest()
  endif()

  generateOsqueryRemoteSerializersSerializerjson()
endfunction()

function(generateOsqueryRemoteSerializersSerializerjson)
  add_osquery_library(osquery_remote_serializers_serializerjson EXCLUDE_FROM_ALL
    json.cpp
  )

  target_link_libraries(osquery_remote_serializers_serializerjson PUBLIC
    osquery_cxx_settings
    osquery_remote_requests
    osquery_utils_json
    thirdparty_boost
  )

  set(public_header_files
    json.h
  )

  generateIncludeNamespace(osquery_remote_serializers_serializerjson "osquery/remote/serializers" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_remote_serializers_remotejsonserializerstests-test COMMAND osquery_remote_serializers_remotejsonserializerstests-test)
endfunction()

function(generateOsqueryRemoteserializersjsontestsTest)
  add_osquery_executable(osquery_remote_serializers_remotejsonserializerstests-test tests/json_serializers_tests.cpp)

  target_link_libraries(osquery_remote_serializers_remotejsonserializerstests-test PRIVATE
    osquery_cxx_settings
    osquery_remote_serializers_serializerjson
    thirdparty_googletest
  )
endfunction()

osqueryRemoteSerializersMain()

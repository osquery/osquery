# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsJsonMain)

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryUtilsJsonJsontestsTest()
  endif()

  generateOsqueryUtilsJson()
endfunction()

function(generateOsqueryUtilsJson)
  add_osquery_library(osquery_utils_json EXCLUDE_FROM_ALL
    json.cpp
  )

  target_link_libraries(osquery_utils_json PUBLIC
    osquery_cxx_settings
    osquery_utils
    osquery_utils_conversions
    osquery_utils_status
    osquery_utils_system_systemutils
    thirdparty_rapidjson
  )

  target_compile_definitions(osquery_utils_json PUBLIC
    RAPIDJSON_HAS_STDSTRING=1
  )

  set(public_header_files
    json.h
  )

  generateIncludeNamespace(osquery_utils_json "osquery/utils/json" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_json_jsontests-test COMMAND osquery_utils_json_jsontests-test)

endfunction()

function(generateOsqueryUtilsJsonJsontestsTest)
  add_osquery_executable(osquery_utils_json_jsontests-test tests/json.cpp)

  target_link_libraries(osquery_utils_json_jsontests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_json
    thirdparty_googletest
  )
endfunction()

osqueryUtilsJsonMain()

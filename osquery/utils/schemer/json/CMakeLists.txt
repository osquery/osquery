# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSchemerJsonMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsSchemerJson()
endfunction()

function(generateOsqueryUtilsSchemerJson)
  add_library(osquery_utils_schemer_json INTERFACE)

  target_link_libraries(osquery_utils_schemer_json INTERFACE
    global_cxx_settings
    osquery_utils_expected
    osquery_utils_json
    osquery_utils_schemer
    thirdparty_rapidjson
  )

  set(public_header_files
    schemer_json.h
    schemer_json_error.h
    schemer_json_impl.h
  )

  generateIncludeNamespace(osquery_utils_schemer_json "osquery/utils/schemer/json" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_schemer_json_tests_schemerjsontests-test COMMAND osquery_utils_schemer_json_tests_schemerjsontests-test)
endfunction()

osqueryUtilsSchemerJsonMain()

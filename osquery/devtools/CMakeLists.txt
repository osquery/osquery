# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryDevtoolsMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryDevtools()
endfunction()

function(generateOsqueryDevtools)
  add_osquery_library(osquery_devtools EXCLUDE_FROM_ALL
    printer.cpp
    shell.cpp
  )

  target_link_libraries(osquery_devtools PUBLIC
    global_cxx_settings
    osquery_config
    osquery_core
    osquery_filesystem
    osquery_process
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    osquery_utils_system_env
    thirdparty_googletest_headers
    thirdparty_linenoise-ng
  )

  set(public_header_files
    devtools.h
  )

  generateIncludeNamespace(osquery_devtools "osquery/devtools" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_devtools_tests_printertests-test COMMAND osquery_devtools_tests_printertests-test)
endfunction()

osqueryDevtoolsMain()

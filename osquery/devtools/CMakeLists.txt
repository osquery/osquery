# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDevtoolsMain)

  if(OSQUERY_BUILD_TESTS)
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
    osquery_cxx_settings
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

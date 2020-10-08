# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryDatabaseMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryDatabaseEphemeral()
  generateOsqueryDatabase()
endfunction()

function(generateOsqueryDatabase)
  add_osquery_library(osquery_database EXCLUDE_FROM_ALL
    database.cpp
  )

  target_link_libraries(osquery_database PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_database_ephemeral
    osquery_utils
    osquery_utils_conversions
    thirdparty_boost
  )

  set(public_header_files
    database.h
    idatabaseinterface.h
  )

  generateIncludeNamespace(osquery_database "osquery/database" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_database_tests-test COMMAND osquery_database_tests-test)
  add_test(NAME osquery_database_tests_results-test COMMAND osquery_database_tests_results-test)
endfunction()

function(generateOsqueryDatabaseEphemeral)
  add_osquery_library(osquery_database_ephemeral EXCLUDE_FROM_ALL
    ephemeral.cpp
  )

  target_link_libraries(osquery_database_ephemeral PUBLIC
    osquery_cxx_settings
    osquery_registry
    thirdparty_boost
  )

  enableLinkWholeArchive(osquery_database_ephemeral)
endfunction()

osqueryDatabaseMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesYaraMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryTablesYaraYaratable()
endfunction()

function(generateOsqueryTablesYaraYaratable)

  if(DEFINED PLATFORM_FREEBSD)
    add_osquery_library(osquery_tables_yara_yaratable INTERFACE)
    return()
  endif()

  set(source_files
    yara.cpp
    yara_utils.cpp
  )

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      yara_events.cpp
    )
  endif()

  add_osquery_library(osquery_tables_yara_yaratable EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_tables_yara_yaratable)

  target_link_libraries(osquery_tables_yara_yaratable PUBLIC
    osquery_cxx_settings
    osquery_config
    osquery_dispatcher
    osquery_events
    osquery_logger
    osquery_registry
    osquery_remote_utility
    osquery_utils_config
    thirdparty_boost
    thirdparty_yara
  )

  set(public_header_files
    yara_utils.h
  )

  generateIncludeNamespace(osquery_tables_yara_yaratable "osquery/tables/yara" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_tables_yara_tests-test COMMAND osquery_tables_yara_tests-test)
  
endfunction()

osqueryTablesYaraMain()

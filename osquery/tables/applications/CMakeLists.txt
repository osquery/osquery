# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesApplicationsMain)

  if(BUILD_TESTING)
    add_subdirectory("posix/tests")
  endif()

  generateOsqueryTablesApplications()
endfunction()

function(generateOsqueryTablesApplications)
  set(source_files
    browser_chrome.cpp
    browser_utils.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/browser_firefox.cpp
      posix/browser_opera.cpp
      posix/carbon_black.cpp
      posix/docker.cpp
      posix/prometheus_metrics.cpp
    )
  endif()

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      atom_packages.cpp
      darwin/browser_plugins.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/carbon_black.cpp
    )
  elseif(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      atom_packages.cpp
    )
  endif()

  add_osquery_library(osquery_tables_applications EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_tables_applications PUBLIC
    global_cxx_settings
    osquery_config
    osquery_filesystem
    osquery_tables_system_systemtable
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_json
    plugins_config_parsers
    thirdparty_boost
  )

  set(public_header_files
    browser_utils.h
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND public_header_files
      posix/prometheus_metrics.h
    )
  endif()

  generateIncludeNamespace(osquery_tables_applications "osquery/tables/applications" "FULL_PATH" ${public_header_files})

  if(DEFINED PLATFORM_POSIX)
    add_test(NAME osquery_tables_applications_posix_tests_prometheusmetricstests-test COMMAND osquery_tables_applications_posix_tests_prometheusmetricstests-test)
  endif()
endfunction()

osqueryTablesApplicationsMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryNumericmonitoringPluginsMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryNumericmonitoringPluginsNumericmonitoringfilesystem()
endfunction()

function(generateOsqueryNumericmonitoringPluginsNumericmonitoringfilesystem)
  # Originally plugins_numericmonitoring_numericmonitoringfilesystem, shortened due to MSBuild not supporting long paths
  add_osquery_library(plugins_numericmonitoring_filesystem EXCLUDE_FROM_ALL
    filesystem.cpp
  )

  enableLinkWholeArchive(plugins_numericmonitoring_filesystem)

  target_link_libraries(plugins_numericmonitoring_filesystem PUBLIC
    osquery_cxx_settings
    osquery_filesystem
    osquery_numericmonitoring
  )

  set(public_header_files
    filesystem.h
  )

  generateIncludeNamespace(plugins_numericmonitoring_filesystem "plugins/numeric_monitoring" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_numericmonitoring_tests_filesystem-test COMMAND plugins_numericmonitoring_tests_filesystem-test)
endfunction()

osqueryNumericmonitoringPluginsMain()

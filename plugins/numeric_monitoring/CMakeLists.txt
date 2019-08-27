# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryNumericmonitoringPluginsMain)

  if(BUILD_TESTING)
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
    global_cxx_settings
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

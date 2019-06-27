# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsNumericmonitoringTestsMain)
  pluginsNumericmonitoringTestsFilesystemtestsTest()
endfunction()

function(pluginsNumericmonitoringTestsFilesystemtestsTest)
  # Originally plugins_numericmonitoring_tests_numericmonitoringfilesystemtests-test, shortened due to MSBuild not supporting long paths
  add_osquery_executable(plugins_numericmonitoring_tests_filesystem-test filesystem.cpp)

  target_link_libraries(plugins_numericmonitoring_tests_filesystem-test PRIVATE
    global_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_numericmonitoring
    osquery_remote_enroll_tlsenroll
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_numericmonitoring_filesystem
    specs_tables
    thirdparty_googletest
  )
endfunction()

pluginsNumericmonitoringTestsMain()

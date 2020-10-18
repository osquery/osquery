# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsNumericmonitoringTestsMain)
  pluginsNumericmonitoringTestsFilesystemtestsTest()
endfunction()

function(pluginsNumericmonitoringTestsFilesystemtestsTest)
  # Originally plugins_numericmonitoring_tests_numericmonitoringfilesystemtests-test, shortened due to MSBuild not supporting long paths
  add_osquery_executable(plugins_numericmonitoring_tests_filesystem-test filesystem.cpp)

  target_link_libraries(plugins_numericmonitoring_tests_filesystem-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_numericmonitoring
    plugins_numericmonitoring_filesystem
    tests_helper
    thirdparty_googletest
  )
endfunction()

pluginsNumericmonitoringTestsMain()

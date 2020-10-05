# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsRemoteEnrollTestsMain)
  add_osquery_executable(plugins_remote_enroll_tlsenrolltests-test tls_enroll_tests.cpp)

  target_link_libraries(plugins_remote_enroll_tlsenrolltests-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_database
    osquery_sql
    osquery_remote_tests_remotetestutils
    plugins_remote_enroll_tlsenroll
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

pluginsRemoteEnrollTestsMain()
# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsRemoteEnrollTestsMain)
  add_osquery_executable(plugins_remote_enroll_tlsenrolltests-test tls_enroll_tests.cpp)

  target_link_libraries(plugins_remote_enroll_tlsenrolltests-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_database
    osquery_sql
    osquery_headers
    osquery_remote_tests_remotetestutils
    plugins_remote_enroll_tlsenroll
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

pluginsRemoteEnrollTestsMain()
# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsConfigTestsMain)
  generatePluginsConfigTestsTlsconfigteststest()
endfunction()

function(generatePluginsConfigTestsTlsconfigteststest)
  add_osquery_executable(plugins_config_tests_tlsconfigtests-test tls_config_tests.cpp)

  target_link_libraries(plugins_config_tests_tlsconfigtests-test PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_headers
    osquery_remote_requests
    osquery_remote_serializers_serializerjson
    osquery_remote_tests_remotetestutils
    osquery_remote_transports_transportstls
    osquery_sql
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_remote_enroll_tlsenroll
    thirdparty_googletest
  )
endfunction()

pluginsConfigTestsMain()
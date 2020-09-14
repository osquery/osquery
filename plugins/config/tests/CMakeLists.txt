# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    osquery_dispatcher_scheduler
    osquery_remote_requests
    osquery_remote_serializers_serializerjson
    osquery_remote_tests_remotetestutils
    osquery_remote_transports_transportstls
    osquery_sql
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_remote_enroll_tlsenroll
    thirdparty_googletest
  )
endfunction()

pluginsConfigTestsMain()

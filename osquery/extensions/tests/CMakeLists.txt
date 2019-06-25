# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExtensionsTestsMain)
  generateOsqueryExtensionsTestsTest()
endfunction()

function(generateOsqueryExtensionsTestsTest)
  add_osquery_executable(osquery_extensions_extensiontests-test extensions.cpp)

  target_link_libraries(osquery_extensions_extensiontests-test PRIVATE
    global_cxx_settings
    osquery_config
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_remote_utility
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryExtensionsTestsMain()

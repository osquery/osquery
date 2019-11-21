# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryWorkerIpcPosixTestsMain)
  generateOsqueryWorkerIpcPosixTestsIpcPipeChannelTest()
endfunction()


function(generateOsqueryWorkerIpcPosixTestsIpcPipeChannelTest)
  set(source_files
    worker_ipc_channels_test.cpp
  )

  add_osquery_executable(osquery_worker_ipc_posix_tests_pipechannel-test ${source_files})

  target_link_libraries(osquery_worker_ipc_posix_tests_pipechannel-test PRIVATE
    osquery_cxx_settings
    osquery_events
    osquery_tables_events_eventstable
    osquery_dispatcher
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    osquery_sdk_pluginsdk
    osquery_events
    osquery_worker_ipc_posix_pipechannel
    thirdparty_googletest
  )
endfunction()

osqueryWorkerIpcPosixTestsMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    osquery_dispatcher
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_registry
    osquery_sql
    osquery_worker_ipc_posix_pipechannel
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryWorkerIpcPosixTestsMain()

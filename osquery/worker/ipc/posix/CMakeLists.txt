# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryWorkerIpcPosixMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryWorkerIpcPosixPipeChannel()
endfunction()

function(generateOsqueryWorkerIpcPosixPipeChannel)
  set(source_files
    pipe_channel.cpp
    pipe_channel_factory.cpp
  )

  set(public_header_files
    pipe_channel.h
    pipe_channel_factory.h
  )

  add_osquery_library(osquery_worker_ipc_posix_pipechannel EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_worker_ipc_posix_pipechannel PUBLIC
    osquery_cxx_settings
    osquery_utils
    osquery_utils_status
    osquery_process
    osquery_worker_ipc_tablechannel
  )

  generateIncludeNamespace(osquery_worker_ipc_posix_pipechannel "osquery/worker/ipc/posix" FILE_ONLY ${public_header_files})

  add_test(NAME osquery_worker_ipc_posix_tests_pipechannel-test COMMAND osquery_worker_ipc_posix_tests_pipechannel-test --gtest_filter=-WorkerIPCChannelsTest.test_pipe_ticket_leak)

  if(OSQUERY_BUILD_ROOT_TESTS)
    add_test(NAME osquery_worker_ipc_posix_tests_pipechannel_root-test COMMAND osquery_worker_ipc_posix_tests_pipechannel-test --gtest_filter=WorkerIPCChannelsTest.test_pipe_ticket_leak)
    set_tests_properties(osquery_worker_ipc_posix_tests_pipechannel_root-test PROPERTIES LABELS "root-required")
  endif()

endfunction()

osqueryWorkerIpcPosixMain()

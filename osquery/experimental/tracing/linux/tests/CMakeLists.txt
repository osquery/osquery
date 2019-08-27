# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExperimentalTracingLinuxTestsMain)

  if(DEFINED PLATFORM_LINUX)
    generateOsqueryExperimentalTracingLinuxTestsEbpftracepointtestsTest()
  endif()
endfunction()

function(generateOsqueryExperimentalTracingLinuxTestsEbpftracepointtestsTest)

  set(source_files
    empty.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files syscall_event.cpp)
  endif()

  add_osquery_executable(osquery_experimental_tracing_linux_tests_ebpftracepointtests-test ${source_files})

  target_link_libraries(osquery_experimental_tracing_linux_tests_ebpftracepointtests-test PRIVATE
    global_cxx_settings
    osquery_experimental_tracing_linux_probesevents
    thirdparty_googletest
  )
endfunction()

osqueryExperimentalTracingLinuxTestsMain()

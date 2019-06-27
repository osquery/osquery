# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExperimentalTracingLinuxMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateExperimentalTracingLinuxProbesevents()
endfunction()

function(generateExperimentalTracingLinuxProbesevents)
  set(library_name "osquery_experimental_tracing_linux_probesevents")

  if(DEFINED PLATFORM_LINUX)
    set(source_files
      ebpf_tracepoint.cpp
      probes.cpp
      syscall_event.cpp
      syscalls_programs.cpp
    )

    add_osquery_library("${library_name}" EXCLUDE_FROM_ALL ${source_files})

    target_link_libraries("${library_name}" PUBLIC
      global_cxx_settings
      osquery_logger
      osquery_utils_conversions
      osquery_utils_expected
      osquery_utils_system_linux_ebpf
      osquery_utils_system_linux_tracing
      osquery_utils
      thirdparty_boost
    )

    set(public_header_files
      ebpf_tracepoint.h
      probes.h
      syscall_event.h
      syscalls_programs.h
    )

    generateIncludeNamespace("${library_name}" "osquery/experimental/tracing/linux" "FILE_ONLY" ${public_header_files})

    add_test(NAME osquery_experimental_tracing_linux_tests_ebpftracepointtests-test COMMAND osquery_experimental_tracing_linux_tests_ebpftracepointtests-test)
  else()
    add_osquery_library("${library_name}" INTERFACE)
  endif()
endfunction()

osqueryExperimentalTracingLinuxMain()

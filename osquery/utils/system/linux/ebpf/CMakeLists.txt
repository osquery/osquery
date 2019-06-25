# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSystemLinuxEbpfMain)

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsSystemLinuxEbpf()
endfunction()

function(generateOsqueryUtilsSystemLinuxEbpf)

  if(DEFINED PLATFORM_LINUX)
    set(source_files
      ebpf.cpp
      map.cpp
      program.cpp
    )

    add_osquery_library(osquery_utils_system_linux_ebpf EXCLUDE_FROM_ALL ${source_files})

    target_link_libraries(osquery_utils_system_linux_ebpf PUBLIC
      global_cxx_settings
      osquery_utils_conversions
      osquery_utils_system_linux_perfevent
      osquery_utils_system_cputopology
      osquery_utils_expected
      osquery_utils_versioning_semantic
      osquery_utils_system_errno
      osquery_logger
      thirdparty_boost
      thirdparty_googletest_headers
    )

    set(public_header_files
      ebpf.h
      map.h
      perf_output.h
      perf_output_impl.h
      program.h
    )

    generateIncludeNamespace(osquery_utils_system_linux_ebpf "osquery/utils/system/linux/ebpf" "FILE_ONLY" ${public_header_files})

    add_test(NAME osquery_utils_system_linux_ebpf_tests-test COMMAND osquery_utils_system_linux_ebpf_tests-test)
  else()
    add_osquery_library(osquery_utils_system_linux_ebpf INTERFACE)
  endif()
endfunction()

osqueryUtilsSystemLinuxEbpfMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSystemLinuxEbpfTestsMain)
  if(DEFINED PLATFORM_LINUX)
    generateOsqueryUtilsSystemLinuxEbpfTestsTest()
  endif()
endfunction()

function(generateOsqueryUtilsSystemLinuxEbpfTestsTest)

  set(source_files
    empty.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    set(platform_source_files
      ebpf.cpp
      map.cpp
      perf_output.cpp
      program.cpp
    )
    list(APPEND source_files ${platform_source_files})
  endif()

  add_osquery_executable(osquery_utils_system_linux_ebpf_tests-test ${source_files})

  target_link_libraries(osquery_utils_system_linux_ebpf_tests-test PRIVATE
    global_cxx_settings
    osquery_utils_system_linux_ebpf
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSystemLinuxEbpfTestsMain()

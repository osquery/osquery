# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    osquery_cxx_settings
    osquery_utils_system_linux_ebpf
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSystemLinuxEbpfTestsMain()

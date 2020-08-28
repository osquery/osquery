# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSystemLinuxProcMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsSystemLinuxProc()
endfunction()

function(generateOsqueryUtilsSystemLinuxProc)

  if(DEFINED PLATFORM_LINUX)
    add_osquery_library(osquery_utils_system_linux_proc EXCLUDE_FROM_ALL proc.cpp)

    target_link_libraries(osquery_utils_system_linux_proc PUBLIC
      osquery_cxx_settings
      thirdparty_boost
    )

    set(public_header_files
      proc.h
    )

    generateIncludeNamespace(osquery_utils_system_linux_proc "osquery/utils/system/linux/proc" "FILE_ONLY" ${public_header_files})
  else()
    add_library(osquery_utils_system_linux_proc INTERFACE)
  endif()

  add_test(NAME osquery_utils_system_linux_proc_proctests-test COMMAND osquery_utils_system_linux_proc_proctests-test)
endfunction()

osqueryUtilsSystemLinuxProcMain()

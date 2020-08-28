# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSystemLinuxProcTestsMain)
  generateOsqueryUtilsSystemLinuxProcTests()
endfunction()

function(generateOsqueryUtilsSystemLinuxProcTests)

  set(source_files
    empty.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      proc.cpp
    )
  endif()

  add_osquery_executable(osquery_utils_system_linux_proc_proctests-test ${source_files})

  # This is a special case for this test, since it requires that its process name starts with proc_tests
  set_target_properties(osquery_utils_system_linux_proc_proctests-test PROPERTIES
    OUTPUT_NAME proc_tests-test
  )

  target_link_libraries(osquery_utils_system_linux_proc_proctests-test PUBLIC
    osquery_cxx_settings
    osquery_utils_system_linux_proc
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSystemLinuxProcTestsMain()

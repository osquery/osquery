# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsPidfileMain)
  set(public_header_files
    pidfile.h
  )

  if(PLATFORM_WINDOWS)
    set(platform_name "windows")
  else()
    set(platform_name "posix")
  endif()

  add_osquery_library(osquery_utils_pidfile EXCLUDE_FROM_ALL
    pidfile.cpp
    pidfile_${platform_name}.cpp

    ${public_header_files}
  )

  target_link_libraries(osquery_utils_pidfile PUBLIC
    osquery_cxx_settings
    osquery_utils_expected
  )

  if(PLATFORM_WINDOWS)
    target_link_libraries(osquery_utils_pidfile PUBLIC
      osquery_utils_conversions
    )
  endif()

  generateIncludeNamespace(
    osquery_utils_pidfile
    "osquery/utils/pidfile"
    "FILE_ONLY"
    ${public_header_files}
  )

  if(OSQUERY_BUILD_TESTS)
    add_osquery_executable(osquery_utils_pidfile_tests-test
      tests/pidfile.cpp
    )

    target_link_libraries(osquery_utils_pidfile_tests-test PRIVATE
      osquery_utils_pidfile
      thirdparty_googletest
    )

    add_test(
      NAME osquery_utils_pidfile_tests-test
      COMMAND osquery_utils_pidfile_tests-test
    )
  endif()
endfunction()

osqueryUtilsPidfileMain()

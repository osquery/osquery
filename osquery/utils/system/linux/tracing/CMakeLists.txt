# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSystemLinuxTracingMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryUtilsSystemLinuxTracing()
endfunction()

function(generateOsqueryUtilsSystemLinuxTracing)

  if(DEFINED PLATFORM_LINUX)
    set(source_files
      native_event.cpp
    )

    add_osquery_library(osquery_utils_system_linux_tracing EXCLUDE_FROM_ALL
      ${source_files}
    )

    target_link_libraries(osquery_utils_system_linux_tracing PUBLIC
      osquery_cxx_settings
      osquery_utils_conversions
      osquery_utils_expected
      osquery_logger
      thirdparty_boost
      thirdparty_googletest_headers
    )

    set(public_header_files
      native_event.h
      types.h
    )

    generateIncludeNamespace(osquery_utils_system_linux_tracing "osquery/utils/system/linux/tracing" "FILE_ONLY" ${public_header_files})

    add_test(NAME osquery_utils_system_linux_tracing_tests-test COMMAND osquery_utils_system_linux_tracing_tests-test)
  else()
    add_osquery_library(osquery_utils_system_linux_tracing INTERFACE)
  endif()
endfunction()

osqueryUtilsSystemLinuxTracingMain()

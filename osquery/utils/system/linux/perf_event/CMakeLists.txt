# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSystemLinuxPerfeventMain)
  generateOsqueryUtilsSystemLinuxPerfevent()
endfunction()

function(generateOsqueryUtilsSystemLinuxPerfevent)

  if(DEFINED PLATFORM_LINUX)
    set(source_files
      perf_event.cpp
    )

    add_osquery_library(osquery_utils_system_linux_perfevent EXCLUDE_FROM_ALL ${source_files})

    target_link_libraries(osquery_utils_system_linux_perfevent PUBLIC
      global_cxx_settings
      osquery_utils_expected
      osquery_utils_system_errno
      thirdparty_boost
    )

    set(public_header_files
      perf_event.h
    )

    generateIncludeNamespace(osquery_utils_system_linux_perfevent "osquery/utils/system/linux/perf_event" "FILE_ONLY" ${public_header_files})
  else()
    add_osquery_library(osquery_utils_system_linux_perfevent INTERFACE)
  endif()
endfunction()

osqueryUtilsSystemLinuxPerfeventMain()

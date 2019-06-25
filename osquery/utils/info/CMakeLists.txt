# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsInfoMain)
  generateOsqueryUtilsInfo()
endfunction()

function(generateOsqueryUtilsInfo)
  add_osquery_library(osquery_utils_info EXCLUDE_FROM_ALL
    platform_type.cpp
    tool_type.cpp
    version.cpp
  )

  target_link_libraries(osquery_utils_info PUBLIC
    global_cxx_settings
    osquery_utils_conversions
    osquery_utils_macros
  )

  target_compile_definitions(osquery_utils_info PUBLIC
    OSQUERY_VERSION=${OSQUERY_VERSION}
    OSQUERY_BUILD_VERSION=${OSQUERY_VERSION}
    OSQUERY_BUILD_SDK_VERSION=${OSQUERY_VERSION}
  )

  set(public_header_files
    platform_type.h
    tool_type.h
    version.h
  )

  generateIncludeNamespace(osquery_utils_info "osquery/utils/info" "FILE_ONLY" ${public_header_files})

endfunction()

osqueryUtilsInfoMain()

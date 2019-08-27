# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsConfigMain)
  generateOsqueryUtilsConfig()
endfunction()

function(generateOsqueryUtilsConfig)
  add_osquery_library(osquery_utils_config EXCLUDE_FROM_ALL
    default_paths.cpp
  )

  target_link_libraries(osquery_utils_config PUBLIC global_cxx_settings)

  set(public_header_files
    default_paths.h
  )

  generateIncludeNamespace(osquery_utils_config "osquery/utils/config" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsConfigMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsConfigMain)
  generateOsqueryUtilsConfig()
endfunction()

function(generateOsqueryUtilsConfig)
  add_osquery_library(osquery_utils_config EXCLUDE_FROM_ALL
    default_paths.cpp
  )

  target_link_libraries(osquery_utils_config PUBLIC osquery_cxx_settings)

  set(public_header_files
    default_paths.h
  )

  generateIncludeNamespace(osquery_utils_config "osquery/utils/config" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsConfigMain()

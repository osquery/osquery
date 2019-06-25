# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsMacrosMain)
  generateOsqueryUtilsMacros()
endfunction()

function(generateOsqueryUtilsMacros)
  add_osquery_library(osquery_utils_macros INTERFACE)

  target_link_libraries(osquery_utils_macros INTERFACE
    global_cxx_settings
  )

  set(public_header_files
    macros.h
  )

  generateIncludeNamespace(osquery_utils_macros "osquery/utils/macros" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsMacrosMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsMacrosMain)
  generateOsqueryUtilsMacros()
endfunction()

function(generateOsqueryUtilsMacros)
  add_osquery_library(osquery_utils_macros INTERFACE)

  target_link_libraries(osquery_utils_macros INTERFACE
    osquery_cxx_settings
  )

  set(public_header_files
    macros.h
  )

  generateIncludeNamespace(osquery_utils_macros "osquery/utils/macros" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsMacrosMain()

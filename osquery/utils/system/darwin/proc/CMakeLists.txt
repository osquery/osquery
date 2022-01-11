# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsSystemDarwinProcMain)
  generateOsqueryUtilsSystemDarwinProc()
endfunction()

function(generateOsqueryUtilsSystemDarwinProc)

  add_osquery_library(osquery_utils_system_darwin_proc
    proc.cpp
  )

  target_link_libraries(osquery_utils_system_darwin_proc PRIVATE
    osquery_cxx_settings
  )

  set(public_header_files
    proc.h
  )

  generateIncludeNamespace(osquery_utils_system_darwin_proc "osquery/utils/system/darwin/proc" "FILE_ONLY" ${public_header_files})

endfunction()

osqueryUtilsSystemDarwinProcMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryHashingMain)
  generateOsqueryHashing()
endfunction()

function(generateOsqueryHashing)
  add_osquery_library(osquery_hashing EXCLUDE_FROM_ALL
    hashing.cpp
  )

  target_link_libraries(osquery_hashing PUBLIC
    osquery_cxx_settings
    osquery_filesystem
    osquery_utils
    osquery_utils_info
    thirdparty_openssl
  )

  set(public_header_files
    hashing.h
  )

  generateIncludeNamespace(osquery_hashing "osquery/hashing" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryHashingMain()

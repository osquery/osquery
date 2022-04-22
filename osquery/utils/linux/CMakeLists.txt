# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsLinuxMain)
  generateOsqueryUtilsLinux()
endfunction()

function(generateOsqueryUtilsLinux)
  set(public_header_files
    dpkg/idpkgquery.h
  )

  add_osquery_library(osquery_utils_linux EXCLUDE_FROM_ALL
    ${public_header_files}

    dpkg/idpkgquery.cpp

    dpkg/dpkgquery.h
    dpkg/dpkgquery.cpp
  )

  target_link_libraries(osquery_utils_linux PUBLIC
    osquery_cxx_settings
    osquery_utils_expected
    osquery_filesystem
    thirdparty_libdpkg
  )

  generateIncludeNamespace(osquery_utils_linux "osquery/utils/linux" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsLinuxMain()

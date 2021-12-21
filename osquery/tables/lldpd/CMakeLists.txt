# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesLldpdMain)
  generateOsqueryTablesLldpdLlpdtable()
endfunction()

function(generateOsqueryTablesLldpdLlpdtable)

  # We want to remove support for lldpd, so skip support for M1
  if(DEFINED PLATFORM_MACOS AND "${TARGET_PROCESSOR}" STREQUAL "aarch64")
    add_osquery_library(osquery_tables_lldpd_llpdtable INTERFACE)
  else()
    add_osquery_library(osquery_tables_lldpd_llpdtable EXCLUDE_FROM_ALL
      lldp_neighbors.cpp
    )

    target_link_libraries(osquery_tables_lldpd_llpdtable PUBLIC
      osquery_cxx_settings
      osquery_core
      osquery_logger
      thirdparty_lldpd
    )
  endif()
endfunction()

osqueryTablesLldpdMain()

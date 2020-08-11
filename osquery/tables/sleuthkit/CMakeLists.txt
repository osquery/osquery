# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesSleuthkitMain)
  generateOsqueryTablesSleuthkit()
endfunction()

function(generateOsqueryTablesSleuthkit)
  add_osquery_library(osquery_tables_sleuthkit_sleuthkittable EXCLUDE_FROM_ALL
    sleuthkit.cpp
  )

  target_link_libraries(osquery_tables_sleuthkit_sleuthkittable PUBLIC
    osquery_cxx_settings
    osquery_hashing
    osquery_logger
    osquery_utils_conversions
    thirdparty_sleuthkit
  )
endfunction()

osqueryTablesSleuthkitMain()

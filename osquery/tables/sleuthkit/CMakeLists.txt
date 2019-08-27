# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesSleuthkitMain)
  generateOsqueryTablesSleuthkit()
endfunction()

function(generateOsqueryTablesSleuthkit)
  add_osquery_library(osquery_tables_sleuthkit_sleuthkittable EXCLUDE_FROM_ALL
    sleuthkit.cpp
  )

  target_link_libraries(osquery_tables_sleuthkit_sleuthkittable PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_hashing
    osquery_logger
    osquery_utils_conversions
    thirdparty_sleuthkit
  )
endfunction()

osqueryTablesSleuthkitMain()

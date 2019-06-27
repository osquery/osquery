# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesCloudMain)
  generateOsqueryTablesCloud()
endfunction()

function(generateOsqueryTablesCloud)
  add_osquery_library(osquery_tables_cloud EXCLUDE_FROM_ALL
    ec2_instance_metadata.cpp
    ec2_instance_tags.cpp
  )

  target_link_libraries(osquery_tables_cloud PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_logger
    osquery_utils_aws
    thirdparty_boost
  )
endfunction()

osqueryTablesCloudMain()

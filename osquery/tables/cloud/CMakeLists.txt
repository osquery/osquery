# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesCloudMain)
  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_WINDOWS)
    generateOsqueryTablesCloudAws()
  endif()

  generateOsqueryTablesCloudAzure()
endfunction()

function(generateOsqueryTablesCloudAws)
  add_osquery_library(osquery_tables_cloud_aws EXCLUDE_FROM_ALL
    aws/ec2_instance_metadata.cpp
    aws/ec2_instance_tags.cpp
  )

  target_link_libraries(osquery_tables_cloud_aws PUBLIC
    osquery_cxx_settings
    osquery_logger
    osquery_utils_aws
    thirdparty_boost
    thirdparty_aws_core
    thirdparty_aws_ec2
  )
endfunction()

function(generateOsqueryTablesCloudAzure)
  add_osquery_library(osquery_tables_cloud_azure EXCLUDE_FROM_ALL
    azure/azure_instance_metadata.cpp
    azure/azure_instance_tags.cpp
  )

  target_link_libraries(osquery_tables_cloud_azure PUBLIC
    osquery_cxx_settings
    osquery_logger
    osquery_utils_azure
    thirdparty_boost
  )
endfunction()

osqueryTablesCloudMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsAzureMain)
  generateOsqueryUtilsAzure()
endfunction()

function(generateOsqueryUtilsAzure)
  add_osquery_library(osquery_utils_azure EXCLUDE_FROM_ALL
    azure_util.cpp
  )

  target_link_libraries(osquery_utils_azure PUBLIC
    osquery_cxx_settings
    osquery_remote_httpclient
    osquery_remote_transports_transportstls
    osquery_utils_json
    osquery_utils_status
  )

  set(public_header_files
    azure_util.h
  )

  generateIncludeNamespace(osquery_utils_azure "osquery/utils/azure" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsAzureMain()

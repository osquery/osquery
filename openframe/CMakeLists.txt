# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryOpenframeMain)
  generateOsqueryOpenframeLibrary()
endfunction()

function(generateOsqueryOpenframeLibrary)
  add_osquery_library(osquery_openframe EXCLUDE_FROM_ALL
    openframe_encryption_service.cpp
    openframe_token_extractor.cpp
    openframe_token_refresher.cpp
    openframe_authorization_manager.cpp
  )

  target_link_libraries(osquery_openframe PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_remote_httpclient
    osquery_remote_requests
    osquery_utils_json
    thirdparty_boost
    thirdparty_glog
  )

  set(public_header_files
    openframe_encryption_service.h
    openframe_token_extractor.h
    openframe_token_refresher.h
    openframe_authorization_manager.h
    openframe_authorization_manager_provider.h
  )

  generateIncludeNamespace(osquery_openframe "openframe" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryOpenframeMain() 
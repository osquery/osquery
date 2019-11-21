# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryWorkerLoggingGlogMain)
  generateOsqueryWorkerLoggingGloglogger()
endfunction()

function(generateOsqueryWorkerLoggingGloglogger)
  set(source_files
    glog_logger.cpp
  )

  set(public_header_files
    glog_logger.h
  )

  add_osquery_library(osquery_worker_logging_glog_logger EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_worker_logging_glog_logger PUBLIC
    osquery_cxx_settings
    osquery_worker_logging_logger
    osquery_logger
  )

  generateIncludeNamespace(osquery_worker_logging_glog_logger "osquery/worker/logging/glog" FULL_PATH ${public_header_files})
endfunction()

osqueryWorkerLoggingGlogMain()

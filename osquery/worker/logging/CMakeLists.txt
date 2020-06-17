# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
function(osqueryWorkerLoggingMain)

  generateOsqueryWorkerLoggingLogger()

  add_subdirectory("glog")

endfunction()

function(generateOsqueryWorkerLoggingLogger)

  add_osquery_library(osquery_worker_logging_logger INTERFACE)

  set(public_header_files
    include/logger.h
    include/glog_logger_types.h
  )

  generateIncludeNamespace(osquery_worker_logging_logger "osquery/worker/logging" FILE_ONLY ${public_header_files})

endfunction()

osqueryWorkerLoggingMain()

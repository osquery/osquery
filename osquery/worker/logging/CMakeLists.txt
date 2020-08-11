# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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

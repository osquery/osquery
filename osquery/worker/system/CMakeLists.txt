# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryWorkerSystemMain)
  generateOsqueryWorkerSystemLinuxMemory()
endfunction()

function(generateOsqueryWorkerSystemLinuxMemory)

  if(DEFINED PLATFORM_LINUX)
    add_osquery_library(osquery_worker_system_linux_memory
      linux/memory.cpp
    )

    target_link_libraries(osquery_worker_system_linux_memory PRIVATE
      osquery_cxx_settings
      osquery_core_init
      osquery_filesystem
      osquery_logger
    )
  else()
    add_library(osquery_worker_system_linux_memory INTERFACE)
  endif()

  set(public_header_files
    memory.h
  )

  generateIncludeNamespace(osquery_worker_system_linux_memory "osquery/worker/system" "FULL_PATH" ${public_header_files})
endfunction()

osqueryWorkerSystemMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(googleLogMain)
  set(disabled_option_list
    WITH_TLS
    WITH_GFLAGS
  )

  set(enabled_option_list
    HAVE_LIB_GFLAGS
    WITH_THREADS
  )

  foreach(option_name ${disabled_option_list})
    set("${option_name}" false CACHE BOOL "" FORCE)
  endforeach()

  foreach(option_name ${enabled_option_list})
    set("${option_name}" true CACHE BOOL "" FORCE)
  endforeach()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)

  copyInterfaceTargetFlagsTo(glog thirdparty_cxx_settings PRIVATE)

  get_target_property(gflags_include_directory thirdparty_gflags INTERFACE_INCLUDE_DIRECTORIES)
  target_include_directories(glog PRIVATE "${gflags_include_directory}")

  # Small hack to set glog's includes as SYSTEM
  get_target_property(glog_include_directory glog INTERFACE_INCLUDE_DIRECTORIES)
  target_include_directories(glog SYSTEM INTERFACE ${glog_include_directory})

  add_library(thirdparty_glog INTERFACE)
  target_link_libraries(thirdparty_glog INTERFACE
    glog
    thirdparty_gflags
  )
endfunction()

googleLogMain()

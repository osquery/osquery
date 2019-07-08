# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(gflagsMain)
  set(BUILD_gflags_nothreads_LIB false CACHE BOOL "" FORCE)
  set(BUILD_gflags_LIB true CACHE BOOL "" FORCE)

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)

  copyInterfaceTargetFlagsTo(gflags_static thirdparty_cxx_settings PRIVATE)

  add_library(thirdparty_gflags INTERFACE)
  target_link_libraries(thirdparty_gflags INTERFACE
    gflags_static
  )

  target_include_directories(thirdparty_gflags INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/submodule/include"
  )
endfunction()

gflagsMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(conveyorMain)

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  message("conveyor library_root:${library_root}")

  add_library(thirdparty_conveyor
    # libconveyor
    "${library_root}/src/conveyor.cpp"
  )

  target_sources(thirdparty_conveyor PRIVATE
    "${library_root}/src/conveyor.cpp"
  )

  target_link_libraries(thirdparty_conveyor PUBLIC
    thirdparty_boost
  )

  target_link_libraries(thirdparty_conveyor PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_conveyor PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_conveyor SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

conveyorMain()

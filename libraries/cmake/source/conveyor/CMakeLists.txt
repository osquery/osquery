# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(conveyorMain)
  set(library_root "${OSQUERY_conveyor_ROOT_DIR}/lib/cpp")

  add_library(thirdparty_conveyor
    # libconveyor
    "${library_root}/src/src/conveyor.cpp"
  )

  target_sources(thirdparty_conveyor PRIVATE
    "${library_root}/src/src/conveyor.cpp"
  )

  target_link_libraries(thirdparty_conveyor PUBLIC
    thirdparty_boost
  )

  target_link_libraries(thirdparty_conveyor PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_conveyor PRIVATE
    "${library_root}/src"
  )

  target_include_directories(thirdparty_conveyor SYSTEM INTERFACE
    "${library_root}/src"
  )
endfunction()

conveyorMain()

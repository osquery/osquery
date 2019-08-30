# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(ssdeepCppMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_ssdeep-cpp
    "${library_root}/match.cpp"
    "${library_root}/engine.cpp"
    "${library_root}/filedata.cpp"
    "${library_root}/dig.cpp"
    "${library_root}/cycles.cpp"
    "${library_root}/helpers.cpp"
    "${library_root}/ui.cpp"
    "${library_root}/fuzzy.c"
    "${library_root}/find-file-size.c"
  )

  target_compile_definitions(thirdparty_ssdeep-cpp PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_ssdeep-cpp PRIVATE
    thirdparty_cxx_settings
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_ssdeep-cpp PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${library_root}"
  )

  target_include_directories(thirdparty_ssdeep-cpp SYSTEM INTERFACE
    "${library_root}"
  )
endfunction()

ssdeepCppMain()

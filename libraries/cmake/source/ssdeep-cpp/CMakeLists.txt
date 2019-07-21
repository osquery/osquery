# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(ssdeepCppMain)
  if(NOT DEFINED PLATFORM_LINUX AND NOT DEFINED PLATFORM_MACOS)
    add_osquery_library(thirdparty_ssdeep-cpp INTERFACE)
    return()
  endif()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_ssdeep-cpp
    "${library_root}/main.cpp"
    "${library_root}/match.cpp"
    "${library_root}/engine.cpp"
    "${library_root}/filedata.cpp"
    "${library_root}/dig.cpp"
    "${library_root}/cycles.cpp"
    "${library_root}/helpers.cpp"
    "${library_root}/ui.cpp"
    "${library_root}/fuzzy.c"
  )

  target_compile_definitions(thirdparty_ssdeep-cpp PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_ssdeep-cpp PUBLIC
    global_cxx_settings
    global_c_settings
    thirdparty_silence_warnings
  )

  target_include_directories(thirdparty_ssdeep-cpp SYSTEM
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/config"
    PUBLIC "${library_root}"
  )
endfunction()

ssdeepCppMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(linenoisengMain)
  set(version "1.0.1")
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_linenoise-ng
    "${library_root}/src/ConvertUTF.cpp"
    "${library_root}/src/linenoise.cpp"
    "${library_root}/src/wcwidth.cpp"
  )

  target_link_libraries(thirdparty_linenoise-ng PUBLIC
    global_cxx_settings
    thirdparty_silence_warnings
  )

  target_include_directories(thirdparty_linenoise-ng SYSTEM PUBLIC
    "${library_root}/include"
  )
endfunction()

linenoisengMain()

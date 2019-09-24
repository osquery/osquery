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

  target_link_libraries(thirdparty_linenoise-ng PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_linenoise-ng PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_linenoise-ng SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

linenoisengMain()

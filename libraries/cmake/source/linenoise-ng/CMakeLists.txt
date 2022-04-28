# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(linenoisengMain)
  set(version "1.0-44-g4754bee")
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

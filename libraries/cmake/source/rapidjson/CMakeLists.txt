# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(rapidjsonMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_rapidjson INTERFACE)
  target_include_directories(thirdparty_rapidjson SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

rapidjsonMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(icuMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/icu4c/source")

  add_library(thirdparty_icu INTERFACE)

  target_include_directories(thirdparty_icu SYSTEM INTERFACE
    "${library_root}/i18n"
    "${library_root}/common"
  )
endfunction()

icuMain()

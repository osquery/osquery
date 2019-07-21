# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(lzmaMain)
  add_osquery_library(thirdparty_lzma INTERFACE)

  if(DEFINED PLATFORM_LINUX)
    set(library_name "liblzma.a")
  else()
    set(library_name "lzma")
  endif()

  target_link_libraries(thirdparty_lzma INTERFACE "${library_name}")
endfunction()

lzmaMain()

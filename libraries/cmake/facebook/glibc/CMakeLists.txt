# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(glibcMain)
  add_library(thirdparty_glibc INTERFACE)

  if(DEFINED PLATFORM_POSIX)
    target_link_options(thirdparty_glibc INTERFACE -ldl)
  endif()

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    target_link_options(thirdparty_glibc INTERFACE -lresolv)
  endif()

  if(DEFINED PLATFORM_LINUX)
    target_link_options(thirdparty_glibc INTERFACE -pthread)
  endif()

  add_library(thirdparty_glibc_resolv ALIAS thirdparty_glibc)
  add_library(thirdparty_glibc_pthread ALIAS thirdparty_glibc)
  add_library(thirdparty_glibc_dl ALIAS thirdparty_glibc)
endfunction()

glibcMain()

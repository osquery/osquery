# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(glibcMain)
  generateGlibcDl()
  generateGlibcResolv()
  generateGlibcPthread()
endfunction()

function(generateGlibcDl)
  add_library(thirdparty_glibc_dl INTERFACE)

  if(DEFINED PLATFORM_POSIX)
    target_link_options(thirdparty_glibc_dl INTERFACE -ldl)
  endif()
endfunction()

function(generateGlibcResolv)
  add_library(thirdparty_glibc_resolv INTERFACE)

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    target_link_options(thirdparty_glibc_resolv INTERFACE -lresolv)
  endif()
endfunction()

function(generateGlibcPthread)
  add_library(thirdparty_glibc_pthread INTERFACE)

  if(DEFINED PLATFORM_LINUX)
    target_link_options(thirdparty_glibc_pthread INTERFACE -pthread)
  endif()
endfunction()

glibcMain()

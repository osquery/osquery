# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(zlibMain)
  set(name "zlib")
  set(version "1.2.11")

  set(anchor_file "lib/libz.a")

  if(DEFINED PLATFORM_LINUX)
    set(hash "c6dfd85ce6c440fbaead6d4a3246d7771ed2b9b9f9e8c43257f57e0881d390e9")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "7f9b44ca67eadb2c6dcf6b86688cb759b77b772858dae2a2380c032c7c1d9edd")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "1685157a99c419e5150cc5f44a61ad1a1f5ddf414bf1a451ed9b6c7faf26d4bc")
    set(anchor_file "lib/zlibstatic.lib")
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

zlibMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(archiveMain)
  set(name "libarchive")
  set(version "3.3.2")

  set(anchor_file "lib/libarchive.a")

  if(DEFINED PLATFORM_LINUX)
    set(hash "6818c2d6c8067918365cb81992f7853b100ef3244b8767bf2d182a1974f225a3")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "a3ec7af1618116fca2008838ef18d2028148b34e215c748da3f25e4053bfe6e8")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "cb1fc7e7ed1c652d7c322f629145749a60586eb8ec033a76025a04f4a42117a5")
    set(anchor_file "lib/archive_static.lib")
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

endfunction()

archiveMain()

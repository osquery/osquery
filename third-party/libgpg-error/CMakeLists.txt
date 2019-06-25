# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libgpgerrorMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libgpg-error")
  set(version "1.27")
  set(hash "6976db62b22844015e934f7225b236c8c4851c515815efa9967575eadd6dabf5")
  set(anchor_file "lib/libgpg-error.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

libgpgerrorMain()

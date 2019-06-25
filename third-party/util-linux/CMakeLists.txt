# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(utillinuxMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "util-linux")
  set(version "2.27.1")
  set(hash "2c2e64f8364afeddc4804716ae835c674d48592c163e59903356de9c3b31da5d")
  set(anchor_file "lib/libmount.a")

  set(additional_libraries
    lib/libblkid.a
    lib/libfdisk.a
    lib/libsmartcols.a
    lib/libuuid.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_libraries})
endfunction()

utillinuxMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libdpkgMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libdpkg")
  set(version "1.19.0.5")
  set(hash "9bd06978cf7caaa68bd607ac817c2fd0f436659a9620f6e8bf0281c4f3106799")
  set(anchor_file "lib/libdpkg.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_zlib)
endfunction()

libdpkgMain()

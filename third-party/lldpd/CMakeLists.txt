# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(lldpdMain)
  set(name "lldpd")
  set(version "0.9.6")

  if(DEFINED PLATFORM_LINUX)
    set(hash "27c0b6e6faf1863db025b95e8217e715cffc51b960b1d09e8fe9235b5ef203d8")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "f9d5d5c0c2514e7d51914ffc747a068b8a82602ca62e44b65f02857f015e0d3f")
  else()
    return()
  endif()

  set(anchor_file "lib/liblldpctl.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

lldpdMain()

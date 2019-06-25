# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libcryptsetupMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libcryptsetup")
  set(version "1.7.5")
  set(hash "ebb53650592212d67ea8c0e49b48891eec64ef370743678881985490c09adeac")
  set(anchor_file "lib/libcryptsetup.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_libgcrypt)

endfunction()

libcryptsetupMain()

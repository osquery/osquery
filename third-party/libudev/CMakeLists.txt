# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libudevMain)

  if (DEFINED PLATFORM_WINDOWS OR DEFINED PLATFORM_MACOS)
    add_osquery_library(thirdparty_libudev INTERFACE)
    return()
  endif()

  set(name "libudev")
  set(version "173")
  set(hash "fc1483fa27cb92876661e453bceef0c5752e4dbe83074a1653928ce44078aa34")
  set(anchor_file "lib/libudev.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

endfunction()

libudevMain()

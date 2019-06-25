# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(ssdeepCppMain)
  set(name "ssdeep-cpp")
  set(version "2.14.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "d8248655050987524dc383d55d7b148803b18331cdbcb8bfd2a8198ca210298b")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "93f11f81eab1cc06bf11fd28bc42d7b9d02972e3705f864a9f8ef0f5ca90abcc")
  else()
    add_osquery_library(thirdparty_ssdeep-cpp INTERFACE)
    return()
  endif()

  set(anchor_file "lib/libfuzzy.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

ssdeepCppMain()

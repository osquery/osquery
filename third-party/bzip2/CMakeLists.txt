# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(bzip2Main)
  set(name "bzip2")
  set(version "1.0.6")

  set(anchor_file "lib/libbz2.a")

  if(DEFINED PLATFORM_MACOS)
    add_osquery_library(thirdparty_bzip2 INTERFACE)
    target_link_libraries(thirdparty_bzip2 INTERFACE "bz2")

    return()

  elseif(DEFINED PLATFORM_LINUX)
    set(hash "1cc3eaf8fe78f19fcae9f71065b04bd2dedb4862081f1d1c96e0668f3df864c8")

  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "11001b5e353bc255a755284b9ed8baed01b6d9fe2a63e5e325124e8b998d48c2")
    set(anchor_file "lib/libbz2.lib")
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

bzip2Main()

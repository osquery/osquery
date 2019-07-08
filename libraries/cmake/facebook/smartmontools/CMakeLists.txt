# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(smartmontoolsMain)
  set(name "smartmontools")
  set(version "0.3.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "a63ecfbd80eb715c1278770c9be72d45578bd9650fc31196956d3a87dd3b2a66")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "2ad496686cef94cf46bbf040d6a1d9aa8e051d2281246bfc7517329fc4695e67")
  else()
    return()
  endif()

  set(anchor_file "lib/libsmartctl.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

smartmontoolsMain()

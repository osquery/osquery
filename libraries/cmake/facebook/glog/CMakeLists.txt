# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(glogMain)
  set(name "glog")
  set(version "0.3.5")

  set(anchor_file "lib/libglog.a")

  if(DEFINED PLATFORM_LINUX)
    set(hash "1291104355f4373f22294d86eeb2e612d03ea1adbf7cbaef2083ca730e9df60c")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "91ccd947175a029da61447cc2f871798dc3756bc3adfc178cc782e4714e5a712")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "7c25024502db7e5ffaa0d7e851450946b9193fb093b815692763b619b4d55723")

    set(anchor_file "lib/glog.lib")
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_gflags)
endfunction()

glogMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libxml2Main)
  set(name "libxml2")
  set(version "2.9.7")

  if(DEFINED PLATFORM_LINUX)
    set(hash "40f341caf6442347a130e614f7d1be3193656b7c5ad86a644a87f3b15282f7bf")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "15c240f914a430036847d19f18be54b86d0c78d54eff601f9b036b63481b420e")
  else()
    add_osquery_library(thirdparty_libxml2 INTERFACE)
    return()
  endif()

  set(anchor_file "lib/libxml2.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_zlib)
endfunction()

libxml2Main()

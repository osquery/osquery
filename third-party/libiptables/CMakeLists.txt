# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libiptablesMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libiptables")
  set(version "1.8.0")
  set(hash "f32841cca13b8273f767d859b6c98f6fe7fea05cfc835ff192c794a5d417ba26")
  set(anchor_file "lib/libip4tc.a")

  set(additional_libraries
    lib/libip6tc.a
    lib/libiptc.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_libraries})
endfunction()

libiptablesMain()

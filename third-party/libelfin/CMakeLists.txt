# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libelfinMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libelfin")
  set(version "0.3")
  set(hash "d3f6611493558a38796072a5464e0c261e6651b5630b51459d9d98dec7d052c9")
  set(anchor_file "lib/libdwarf++.a")

  set(additional_lib
    lib/libelf++.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_lib})
endfunction()

libelfinMain()

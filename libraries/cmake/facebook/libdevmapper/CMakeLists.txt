# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libdevmapperMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libdevmapper")
  set(version "2.2.02.173")
  set(hash "54fc7a991f42e3693fa3aa9cafe39f0b65a6fe29620f3146fd05f1a1f1bf1eae")
  set(anchor_file "lib/liblvm2app.a")

  set(additional_libraries
    lib/liblvm-internal.a
    lib/libdevmapper.a
    lib/libdaemonclient.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_libraries})
endfunction()

libdevmapperMain()

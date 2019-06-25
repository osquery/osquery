# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(boostMain)
  set(name "boost")
  set(version "1.66.0")

  set(anchor_file "lib/libboost_chrono-mt.a")

  set(additional_libraries
    lib/libboost_context-mt.a
    lib/libboost_coroutine-mt.a
    lib/libboost_filesystem-mt.a
    lib/libboost_regex-mt.a
    lib/libboost_thread-mt.a
    lib/libboost_system-mt.a
  )

  if(DEFINED PLATFORM_LINUX)
    set(hash "3a24d65730beb3a718ee443eaedac40033d349582eeb83664ea2529080c812ba")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "69c884d27838a11f9a45b78e03eb12a425d554dac4ad8c6ef19f91e63e945286")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "5530174b75b67c3c8e59f2ae62c3e18fea1b5e55c795ff19b40fb75cf93dfb51")
    set(anchor_file "lib/libboost_chrono-mt-s.lib")

    set(additional_libraries
      lib/libboost_context-mt-s.lib
      lib/libboost_coroutine-mt-s.lib
      lib/libboost_filesystem-mt-s.lib
      lib/libboost_regex-mt-s.lib
      lib/libboost_thread-mt-s.lib
      lib/libboost_system-mt-s.lib
    )
  else()
    message(SEND_ERROR "Unsupported platform")
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_libraries})
endfunction()

boostMain()

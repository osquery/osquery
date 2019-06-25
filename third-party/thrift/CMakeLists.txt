# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(thrifMain)
  set(name "thrift")
  set(version "0.11.0")

  set(anchor_file "lib/libthrift.a")

  set(additional_library
    "lib/libthriftz.a"
  )

  if(DEFINED PLATFORM_LINUX)
    set(hash "32d0a6c2220114272fe6819a30b5ddfe000d9bed03f0d1fc3b6b68d438b5cc1e")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "11a4f8565728e73a54808bf55517014cc69597ef965c3b2b7ebeb52f6dd43c26")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "8b115b46d7fbae38eafbd50c4fabca1dd7e14a86ad52bda601ec374b44dc5373")

    set(anchor_file "lib/parse.lib")

    set(additional_libraries
      lib/thriftzmt.lib
      lib/thriftmt.lib
    )
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_libraries})

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_boost)
endfunction()

thrifMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(linenoisengMain)
  set(name "linenoise-ng")
  set(version "1.0.1")
  set(hash "")

  set(anchor_file "lib/liblinenoise.a")

  if(DEFINED PLATFORM_LINUX)
    set(hash "604e50db04ab61ef592bcb96941bb30b67e976ac5487f904eab6927d96b9f5e9")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "78030ddb7041e86cfdd8db60bf446a147fb4c82959319597b09dcf0877337cf9")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "6dbc0acd2c2c02a93136c5a673f87463e3f619ee07fa6b20c5806a2d5bef7c05")
    set(anchor_file "lib/linenoise.lib")
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")
endfunction()

linenoisengMain()

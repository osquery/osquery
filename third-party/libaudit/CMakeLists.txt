# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libauditMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libaudit")
  set(version "2.4.2")
  set(hash "4e87a234f68eb8686ab3fa9096ffd664a899efc8e7839c767abd60ac956f6688")
  set(anchor_file "lib/libaudit.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

endfunction()

libauditMain()

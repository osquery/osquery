# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(yaraMain)
  set(name "yara")
  set(version "3.7.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "4706e8312c531c436b03be4ea429a94dbd06e2cd392764febc9e259777c8fc98")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "8cf4dfeb1e5f93fda206a200c1bce070c11bd486c1c335ede570980cdd196b0b")
  else()
    return()
  endif()

  set(anchor_file "lib/libyara.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_openssl)
endfunction()

yaraMain()

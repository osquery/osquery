# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(opensslMain)
  set(name "openssl")
  set(version "1.0.2o")

  set(anchor_file "lib/libssl.a")

  set(additional_lib
    lib/libcrypto.a
  )

  if(DEFINED PLATFORM_LINUX)
    set(hash "73472b9cf2d050b3cdda404144d28244b52d89b538b82de95acaaa98e282a1ea")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "39c59c34a497b365af0895de2b3e65e89c03f14c846084902ad3a77f943c3457")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "71144e5754cb19c32bad2ba298a3cf24e3fde4a012334c622c84e9a8cdc91ef8")
    set(anchor_file "lib/libeay32.lib")

    set(additional_lib
      lib/ssleay32.lib
    )
  else()
    return()
  endif()

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "${anchor_file}" ${additional_lib})
endfunction()

opensslMain()

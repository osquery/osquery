# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libgpgerrorMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libgpg-error
    "${library_root}/src/code-to-errno.c"
    "${library_root}/src/posix-lock.c"
    "${library_root}/src/posix-thread.c"
    "${library_root}/src/version.c"
    "${library_root}/src/estream-printf.c"
    "${library_root}/src/code-from-errno.c"
    "${library_root}/src/strsource.c"
    "${library_root}/src/estream.c"
    "${library_root}/src/init.c"
    "${library_root}/src/strerror.c"
    "${library_root}/src/visibility.c"
    "${library_root}/src/b64dec.c"
  )

  target_compile_definitions(thirdparty_libgpg-error PRIVATE
    HAVE_CONFIG_H
    LOCALEDIR="/usr/local/share/locale"
    PKGDATADIR="/usr/local/share/libgpg-error"
  )

  target_link_libraries(thirdparty_libgpg-error PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libgpg-error PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}"
    "${library_root}"
  )

  target_include_directories(thirdparty_libgpg-error SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}"
  )
endfunction()

libgpgerrorMain()

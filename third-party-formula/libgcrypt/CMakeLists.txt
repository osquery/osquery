# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libgcryptMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libgcrypt")
  set(anchor_file "lib/libgcrypt.a")

  importThirdPartyBinaryLibrary("${name}" "${anchor_file}")

  target_link_libraries("thirdparty_${name}" INTERFACE thirdparty_libgpg-error)

  set(dependencies libgpg-error)
  definePrebuiltProject(${name}
    URL https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.1.tar.bz2
    SHA256 7a2875f8b1ae0301732e878c0cca2c9664ff09ef71408f085c50e332656a78b3
    DEPENDS ${dependencies}
    CONFIGURE
      ./configure
        --prefix=<INSTALL_DIR>
        --disable-shared
        --enable-static
        --disable-avx-support
        --disable-avx2-support
        --disable-drng-support
        --disable-pclmul-support
        --disable-sse41-support
        --disable-optimization
        --disable-asm
        --disable-jent-support
        --with-libgpg-error-prefix=<INSTALL_DIR>
        --with-gpg-error-prefix=<INSTALL_DIR> &&
      ed -s - config.h < ${CMAKE_CURRENT_SOURCE_DIR}/libgcrypt-1.8.1-1-config.h.ed
    BUILD
      cd <SOURCE_DIR>/cipher && $(MAKE) &&
      cd <SOURCE_DIR>/random && $(MAKE) &&
      cd <SOURCE_DIR>/mpi && $(MAKE) &&
      cd <SOURCE_DIR>/compat && $(MAKE) &&
      cd <SOURCE_DIR>/src && $(MAKE)
    INSTALL
      cd src && $(MAKE) install
    BUILD_IN_SOURCE ON
  )
endfunction()

libgcryptMain()

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libcryptsetupMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libcryptsetup
    "${library_root}/lib/crypto_backend/pbkdf_check.c"
    "${library_root}/lib/crypto_backend/crc32.c"
    "${library_root}/lib/crypto_backend/crypto_cipher_kernel.c"
    "${library_root}/lib/crypto_backend/crypto_storage.c"
    "${library_root}/lib/crypto_backend/crypto_gcrypt.c"
    "${library_root}/lib/luks1/af.c"
    "${library_root}/lib/luks1/keyencryption.c"
    "${library_root}/lib/luks1/keymanage.c"
    "${library_root}/lib/loopaes/loopaes.c"
    "${library_root}/lib/verity/verity_hash.c"
    "${library_root}/lib/verity/verity.c"
    "${library_root}/lib/tcrypt/tcrypt.c"
    "${library_root}/lib/utils_device.c"
    "${library_root}/lib/libdevmapper.c"
    "${library_root}/lib/utils_wipe.c"
    "${library_root}/lib/utils.c"
    "${library_root}/lib/utils_benchmark.c"
    "${library_root}/lib/setup.c"
    "${library_root}/lib/utils_crypt.c"
    "${library_root}/lib/utils_loop.c"
    "${library_root}/lib/utils_devpath.c"
    "${library_root}/lib/utils_fips.c"
    "${library_root}/lib/volumekey.c"
    "${library_root}/lib/crypt_plain.c"
    "${library_root}/lib/random.c"
  )

  target_compile_definitions(thirdparty_libcryptsetup PRIVATE
    DATADIR="/usr/share"
    HAVE_CONFIG_H
    LIBDIR="/usr/lib"
    LOCALEDIR="/usr/share/locale"
    PREFIX="/usr"
    SYSCONFDIR="/etc"
    VERSION="1.7.5"
  )

  target_compile_options(thirdparty_libcryptsetup PRIVATE
    -include config.h
  )

  target_link_libraries(thirdparty_libcryptsetup PUBLIC
    thirdparty_util-linux
    thirdparty_libgcrypt
    thirdparty_libdevmapper
    thirdparty_popt
  )

  target_link_libraries(thirdparty_libcryptsetup PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libcryptsetup PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${library_root}"
    "${library_root}/lib"
    "${library_root}/lib/crypto_backend"
    "${library_root}/lib/loopaes"
    "${library_root}/lib/luks1"
    "${library_root}/lib/tcrypt"
    "${library_root}/lib/verity"
    "${library_root}/src"
  )

  target_include_directories(thirdparty_libcryptsetup SYSTEM INTERFACE
    "${library_root}/lib"
  )
endfunction()

libcryptsetupMain()

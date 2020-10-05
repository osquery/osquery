# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libgcryptMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  set(generated_root "${CMAKE_CURRENT_SOURCE_DIR}/generated/${TARGET_PROCESSOR}")

  add_library(thirdparty_libgcrypt
    "${library_root}/cipher/cipher-ctr.c"
    "${library_root}/cipher/cipher-ofb.c"
    "${library_root}/cipher/cipher-cbc.c"
    "${library_root}/cipher/cipher.c"
    "${library_root}/cipher/cipher-cfb.c"
    "${library_root}/cipher/cipher-aeswrap.c"
    "${library_root}/cipher/crc-intel-pclmul.c"
    "${library_root}/cipher/cipher-gcm.c"
    "${library_root}/cipher/cipher-cmac.c"
    "${library_root}/cipher/cipher-ccm.c"
    "${library_root}/cipher/cipher-poly1305.c"
    "${library_root}/cipher/cipher-ocb.c"
    "${library_root}/cipher/cipher-xts.c"
    "${library_root}/cipher/cipher-selftest.c"
    "${library_root}/cipher/pubkey.c"
    "${library_root}/cipher/pubkey-util.c"
    "${library_root}/cipher/mac-hmac.c"
    "${library_root}/cipher/hmac-tests.c"
    "${library_root}/cipher/mac.c"
    "${library_root}/cipher/md.c"
    "${library_root}/cipher/mac-cmac.c"
    "${library_root}/cipher/mac-poly1305.c"
    "${library_root}/cipher/kdf.c"
    "${library_root}/cipher/poly1305.c"
    "${library_root}/cipher/mac-gmac.c"
    "${library_root}/cipher/primegen.c"
    "${library_root}/cipher/dsa-common.c"
    "${library_root}/cipher/hash-common.c"
    "${library_root}/cipher/rsa-common.c"
    "${library_root}/cipher/arcfour.c"
    "${library_root}/cipher/blowfish.c"
    "${library_root}/cipher/cast5.c"
    "${library_root}/cipher/des.c"
    "${library_root}/cipher/rijndael.c"
    "${library_root}/cipher/rijndael-padlock.c"
    "${library_root}/cipher/twofish.c"
    "${library_root}/cipher/serpent.c"
    "${library_root}/cipher/rfc2268.c"
    "${library_root}/cipher/seed.c"
    "${library_root}/cipher/camellia.c"
    "${library_root}/cipher/camellia-glue.c"
    "${library_root}/cipher/idea.c"
    "${library_root}/cipher/salsa20.c"
    "${library_root}/cipher/chacha20.c"
    "${library_root}/cipher/dsa.c"
    "${library_root}/cipher/rsa.c"
    "${library_root}/cipher/elgamal.c"
    "${library_root}/cipher/ecc.c"
    "${library_root}/cipher/ecc-curves.c"
    "${library_root}/cipher/ecc-misc.c"
    "${library_root}/cipher/ecc-eddsa.c"
    "${library_root}/cipher/ecc-ecdsa.c"
    "${library_root}/cipher/ecc-gost.c"
    "${library_root}/cipher/gostr3411-94.c"
    "${library_root}/cipher/crc.c"
    "${library_root}/cipher/stribog.c"
    "${library_root}/cipher/md5.c"
    "${library_root}/cipher/md4.c"
    "${library_root}/cipher/rmd160.c"
    "${library_root}/cipher/sha256.c"
    "${library_root}/cipher/sha512.c"
    "${library_root}/cipher/keccak.c"
    "${library_root}/cipher/whirlpool.c"
    "${library_root}/cipher/tiger.c"
    "${library_root}/cipher/blake2.c"
    "${library_root}/cipher/sha1.c"
    "${library_root}/cipher/scrypt.c"
    "${library_root}/cipher/gost28147.c"
    "${library_root}/compat/compat.c"
    "${library_root}/mpi/mpi-add.c"
    "${library_root}/mpi/mpi-gcd.c"
    "${library_root}/mpi/mpi-mul.c"
    "${library_root}/mpi/mpi-cmp.c"
    "${library_root}/mpi/mpi-inline.c"
    "${library_root}/mpi/mpi-bit.c"
    "${library_root}/mpi/mpi-div.c"
    "${library_root}/mpi/mpi-mod.c"
    "${library_root}/mpi/mpi-inv.c"
    "${library_root}/mpi/mpi-pow.c"
    "${library_root}/mpi/mpi-scan.c"
    "${library_root}/mpi/mpicoder.c"
    "${library_root}/mpi/mpih-div.c"
    "${library_root}/mpi/mpi-mpow.c"
    "${library_root}/mpi/mpiutil.c"
    "${library_root}/mpi/mpih-mul.c"
    "${library_root}/mpi/ec-ed25519.c"
    "${library_root}/mpi/ec.c"
    "${library_root}/random/random.c"
    "${library_root}/random/random-csprng.c"
    "${library_root}/random/random-system.c"
    "${library_root}/random/rndjent.c"
    "${library_root}/random/rndhw.c"
    "${library_root}/random/random-drbg.c"
    "${library_root}/random/rndlinux.c"
    "${library_root}/src/hwfeatures.c"
    "${library_root}/src/sexp.c"
    "${library_root}/src/visibility.c"
    "${library_root}/src/global.c"
    "${library_root}/src/hmac256.c"
    "${library_root}/src/stdmem.c"
    "${library_root}/src/misc.c"
    "${library_root}/src/missing-string.c"
    "${library_root}/src/secmem.c"
    "${library_root}/src/fips.c"
    "${library_root}/src/context.c"

    "${generated_root}/mpi/mpih-lshift.c"
    "${generated_root}/mpi/mpih-rshift.c"
  )

  if(TARGET_PROCESSOR STREQUAL "aarch64")
    target_sources(thirdparty_libgcrypt PRIVATE
      "${library_root}/src/hwf-arm.c"
      "${library_root}/cipher/rijndael-armv8-ce.c")
  else()
    target_sources(thirdparty_libgcrypt PRIVATE
      "${library_root}/cipher/crc-intel-pclmul.c"
      "${library_root}/cipher/rijndael-ssse3-amd64.c"
      "${library_root}/cipher/rijndael-aesni.c"
      "${library_root}/src/hwf-x86.c"
      "${generated_root}/mpi/mpih-add1.c"
      "${generated_root}/mpi/mpih-sub1.c"
      "${generated_root}/mpi/mpih-mul1.c"
      "${generated_root}/mpi/mpih-mul2.c"
      "${generated_root}/mpi/mpih-mul3.c")
  endif()

  # Some of these files don't play nice with clang; let's compile them
  # manually with gcc and then link in the object files
  #
  # The avx and avx2 files are NOT included here so that we are compatible
  # with more processors. Note that the configuration flags to disable them
  # were not enough! Make sure all the AVX/AVX2 options are off when re-generating
  # a new config file!
  if(TARGET_PROCESSOR STREQUAL "aarch64")
    set(asm_source_list
      "${library_root}/cipher/rijndael-aarch64.S"
      "${library_root}/cipher/rijndael-armv8-aarch64-ce.S"
      "${library_root}/cipher/twofish-aarch64.S"
      "${library_root}/cipher/camellia-aarch64.S"
      "${library_root}/cipher/sha256-armv8-aarch64-ce.S"
      "${library_root}/cipher/sha1-armv8-aarch64-ce.S"
      "${library_root}/cipher/cipher-gcm-armv8-aarch64-ce.S"

      "${generated_root}/mpi/mpih-add1-asm.S"
      "${generated_root}/mpi/mpih-sub1-asm.S"
      "${generated_root}/mpi/mpih-mul1-asm.S"
      "${generated_root}/mpi/mpih-mul2-asm.S"
      "${generated_root}/mpi/mpih-mul3-asm.S"
      )
  else()
    set(asm_source_list
      "${library_root}/cipher/arcfour-amd64.S"
      "${library_root}/cipher/blowfish-amd64.S"
      "${library_root}/cipher/cast5-amd64.S"
      "${library_root}/cipher/des-amd64.S"
      "${library_root}/cipher/rijndael-amd64.S"
      "${library_root}/cipher/twofish-amd64.S"
      "${library_root}/cipher/salsa20-amd64.S"

      "${library_root}/cipher/serpent-sse2-amd64.S"
      "${library_root}/cipher/chacha20-sse2-amd64.S"
      "${library_root}/cipher/poly1305-sse2-amd64.S"
      "${library_root}/cipher/whirlpool-sse2-amd64.S"

      "${library_root}/cipher/rijndael-ssse3-amd64-asm.S"
      "${library_root}/cipher/chacha20-ssse3-amd64.S"
      "${library_root}/cipher/sha256-ssse3-amd64.S"
      "${library_root}/cipher/sha512-ssse3-amd64.S"
      "${library_root}/cipher/sha1-ssse3-amd64.S"
    )
  endif()

  add_custom_target(thirdparty_libgcrypt_asm)
  add_dependencies(thirdparty_libgcrypt thirdparty_libgcrypt_asm)

  set(asm_source_index 0)

  foreach(asm_source ${asm_source_list})
    get_filename_component(asm_source_name "${asm_source}" NAME)
    set(asm_object "${CMAKE_CURRENT_BINARY_DIR}/${asm_source_name}.o")

    add_custom_command(
      OUTPUT "${asm_object}"
      COMMAND ${CMAKE_C_COMPILER} -fno-integrated-as -DHAVE_CONFIG_H -O2 -g -DNDEBUG -fPIC -std=gnu11 -o "${asm_object}" -c "${asm_source}" "-I${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
      DEPENDS "${asm_source}"
      COMMENT "Assembling: ${asm_source}"
      VERBATIM
    )

    add_custom_target("thirdparty_${asm_source_index}_builder"
      DEPENDS "${asm_object}"
    )

    add_dependencies(thirdparty_libgcrypt_asm
      "thirdparty_${asm_source_index}_builder"
    )

    list(APPEND asm_object_library "${asm_object}")

    math(EXPR asm_source_index "${asm_source_index} + 1")
  endforeach()

  target_sources(thirdparty_libgcrypt PRIVATE ${asm_object_library})

  target_compile_definitions(thirdparty_libgcrypt PRIVATE
    HAVE_CONFIG_H
  )

  target_link_libraries(thirdparty_libgcrypt PUBLIC
    thirdparty_libgpg-error
  )

  target_link_libraries(thirdparty_libgcrypt PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libgcrypt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"

    "${library_root}/src"
    "${library_root}/mpi"
    "${library_root}/cipher"

    "${generated_root}/src"
    "${generated_root}/mpi"
    "${generated_root}/cipher"
  )

  target_include_directories(thirdparty_libgcrypt SYSTEM INTERFACE
    "${generated_root}/src"
  )
endfunction()

libgcryptMain()

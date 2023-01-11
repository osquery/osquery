# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(yaraMain)
  set(library_root "${OSQUERY_yara_ROOT_DIR}/libyara")

  set(sources
    "${library_root}/ahocorasick.c"
    "${library_root}/arena.c"
    "${library_root}/atoms.c"
    "${library_root}/base64.c"
    "${library_root}/bitmask.c"
    "${library_root}/compiler.c"
    "${library_root}/endian.c"
    "${library_root}/exec.c"
    "${library_root}/exefiles.c"
    "${library_root}/filemap.c"
    "${library_root}/grammar.c"
    "${library_root}/hash.c"
    "${library_root}/hex_grammar.c"
    "${library_root}/hex_lexer.c"
    "${library_root}/lexer.c"
    "${library_root}/libyara.c"
    "${library_root}/mem.c"
    "${library_root}/modules.c"
    "${library_root}/notebook.c"
    "${library_root}/object.c"
    "${library_root}/parser.c"
    "${library_root}/proc.c"
    "${library_root}/re.c"
    "${library_root}/re_grammar.c"
    "${library_root}/re_lexer.c"
    "${library_root}/rules.c"
    "${library_root}/scan.c"
    "${library_root}/scanner.c"
    "${library_root}/sizedstr.c"
    "${library_root}/stack.c"
    "${library_root}/stopwatch.c"
    "${library_root}/stream.c"
    "${library_root}/strutils.c"
    "${library_root}/threading.c"
    "${library_root}/modules/console/console.c"
    "${library_root}/modules/dex/dex.c"
    "${library_root}/modules/dotnet/dotnet.c"
    "${library_root}/modules/elf/elf.c"
    "${library_root}/modules/hash/hash.c"
    "${library_root}/modules/macho/macho.c"
    "${library_root}/modules/math/math.c"
    "${library_root}/modules/pe/pe.c"
    "${library_root}/modules/pe/pe_utils.c"
    "${library_root}/modules/tests/tests.c"
    "${library_root}/modules/time/time.c"
  )

  set(yara_strutils_definitions
    "xtoi=yara_strutils_xtoi"
    "strnlen_w=yara_strutils_strnlen_w"
    "strlcpy_w=yara_strutils_strlcpy_w"
    "strcmp_w=yara_strutils_strcmp_w"
    "yr_isalnum=yara_strutils_isalnum"
  )

  if(PLATFORM_POSIX)
    list(APPEND sources
      "${library_root}/modules/magic/magic.c"
    )

    if(PLATFORM_LINUX)
      list(APPEND sources
        "${library_root}/proc/linux.c"
      )
    elseif(PLATFORM_MACOS)
      list(APPEND sources
        "${library_root}/proc/mach.c"
      )
    else()
      message(FATAL_ERROR "Unsupported posix platform")
    endif()
  elseif(PLATFORM_WINDOWS)
    list(APPEND sources
      "${library_root}/proc/windows.c"
    )
  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  add_library(thirdparty_yara ${sources})

  target_link_libraries(thirdparty_yara
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_openssl
  )

  target_compile_definitions(thirdparty_yara PRIVATE
    DOTNET_MODULE
    HASH_MODULE
    HAVE_LIBCRYPTO=1
    ${yara_strutils_definitions}
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_yara PRIVATE
      STDC_HEADERS=1
      HAVE_SYS_TYPES_H=1
      HAVE_SYS_STAT_H=1
      HAVE_STDLIB_H=1
      HAVE_STRING_H=1
      HAVE_STRINGS_H=1
      HAVE_INTTYPES_H=1
      HAVE_STDINT_H=1
      HAVE_UNISTD_H=1
      HAVE_DLFCN_H=1
      HAVE_LIBM=1
      HAVE_MEMMEM=1
      HAVE_TIMEGM=1
      HAVE_CLOCK_GETTIME=1
      HAVE_STDBOOL_H=1
      HAVE_MAGIC_H=1
      HAVE_LIBMAGIC=1
      HAVE_OPENSSL_MD5_H=1
      HAVE_OPENSSL_SHA_H=1
      HAVE_OPENSSL_ASN1_H=1
      HAVE_OPENSSL_CRYPTO_H=1
      HAVE_OPENSSL_BIO_H=1
      HAVE_OPENSSL_PKCS7_H=1
      HAVE_OPENSSL_X509_H=1
      HAVE_OPENSSL_SAFESTACK_H=1
      HAVE_SCAN_PROC_IMPL=1
      MAGIC_MODULE
      MACHO_MODULE
      DEX_MODULE
    )

    target_link_libraries(thirdparty_yara PUBLIC
      thirdparty_libmagic
    )

    if(PLATFORM_LINUX)
      list(APPEND yara_strutils_definitions
        "strlcpy=yara_strutils_strlcpy"
        "strlcat=yara_strutils_strlcat"
      )

      target_compile_definitions(thirdparty_yara PRIVATE
        HAVE_MEMORY_H=1
        USE_LINUX_PROC
        _GNU_SOURCE
      )

    elseif(PLATFORM_MACOS)
      target_compile_definitions(thirdparty_yara PRIVATE
        HAVE_STDIO_H=1
        HAVE_STRLCAT=1
        HAVE_STRLCPY=1
        YYTEXT_POINTER=1
        USE_MACH_PROC
        _THREAD_SAFE
      )
    endif()
  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_WINDOWS_PROC
    )
  endif()

  target_include_directories(thirdparty_yara PRIVATE
    "${library_root}/include"
    "${library_root}"
  )

  target_include_directories(thirdparty_yara SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

yaraMain()

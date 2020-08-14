# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(yaraMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/libyara")

  add_library(thirdparty_yara
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
    "${library_root}/modules/demo/demo.c"
    "${library_root}/modules/dex/dex.c"
    "${library_root}/modules/dotnet/dotnet.c"
    "${library_root}/modules/elf/elf.c"
    "${library_root}/modules/hash/hash.c"
    "${library_root}/modules/macho/macho.c"
    "${library_root}/modules/math/math.c"
    "${library_root}/modules/module_list"
    "${library_root}/modules/pe/pe.c"
    "${library_root}/modules/pe/pe_utils.c"
    "${library_root}/modules/tests/tests.c"
    "${library_root}/modules/time/time.c"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_yara PRIVATE
      "${library_root}/proc/windows.c"
    )
  elseif(DEFINED PLATFORM_LINUX)
    target_sources(thirdparty_yara PRIVATE
      "${library_root}/proc/linux.c"
      "${library_root}/modules/magic/magic.c"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_sources(thirdparty_yara PRIVATE
      "${library_root}/proc/mach.c"
      "${library_root}/modules/magic/magic.c"
    )
  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  target_compile_definitions(thirdparty_yara PRIVATE
    PACKAGE_NAME=\"yara\"
    PACKAGE_TARNAME=\"yara\"
    PACKAGE_VERSION=\"4.0.2\"
    PACKAGE_STRING=\"yara\ 4.0.2\"
    PACKAGE_BUGREPORT=\"vmalvarez@virustotal.com\"
    PACKAGE_URL=\"\"
    PACKAGE=\"yara\"
    VERSION=\"4.0.2\"
    YYTEXT_POINTER=1
    STDC_HEADERS=1
    HAVE_SYS_TYPES_H=1
    HAVE_SYS_STAT_H=1
    HAVE_STDLIB_H=1
    HAVE_STRING_H=1
    HAVE_MEMORY_H=1
    HAVE_STRINGS_H=1
    HAVE_INTTYPES_H=1
    HAVE_STDINT_H=1
    HAVE_UNISTD_H=1
    HAVE_DLFCN_H=1
    LT_OBJDIR=\".libs/\"
    HAVE_LIBM=1
    HAVE_STDBOOL_H=1
    HAVE_CLOCK_GETTIME=1
    HAVE_SCAN_PROC_IMPL=1
    HAVE_LIBCRYPTO=1
    HAVE_OPENSSL_MD5_H=1
    HAVE_OPENSSL_SHA_H=1
    HAVE_OPENSSL_ASN1_H=1
    HAVE_OPENSSL_CRYPTO_H=1
    HAVE_OPENSSL_BIO_H=1
    HAVE_OPENSSL_PKCS7_H=1
    HAVE_OPENSSL_X509_H=1
    HAVE_OPENSSL_SAFESTACK_H=1
  )

  if(DEFINED PLATFORM_LINUX)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_LINUX_PROC
      HAVE_MEMMEM=1
      HAVE_TIMEGM=1
    )

    target_link_libraries(thirdparty_yara PUBLIC
      thirdparty_openssl
      thirdparty_libmagic
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_MACH_PROC
      HAVE_MEMMEM=1
      HAVE_TIMEGM=1
    )

    target_link_libraries(thirdparty_yara PUBLIC
      thirdparty_openssl
      thirdparty_libmagic
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_WINDOWS_PROC
      HAVE_MEMMEM=0
      HAVE_TIMEGM=0
    )

    target_link_libraries(thirdparty_yara PUBLIC
      thirdparty_openssl
    )
  endif()

  target_link_libraries(thirdparty_yara PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_yara PRIVATE
    "${library_root}/include"
    "${library_root}"
  )

  target_include_directories(thirdparty_yara SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

yaraMain()

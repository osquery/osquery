# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(yaraMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/libyara")

  add_library(thirdparty_yara
    "${library_root}/ahocorasick.c"
    "${library_root}/arena.c"
    "${library_root}/atoms.c"
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
    "${library_root}/modules/demo.c"
    "${library_root}/modules/dex.c"
    "${library_root}/modules/dotnet.c"
    "${library_root}/modules/elf.c"
    "${library_root}/modules/hash.c"
    "${library_root}/modules/macho.c"
    "${library_root}/modules/magic.c"
    "${library_root}/modules/math.c"
    "${library_root}/modules/module_list"
    "${library_root}/modules/pe.c"
    "${library_root}/modules/pe_utils.c"
    "${library_root}/modules/tests.c"
    "${library_root}/modules/time.c"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_yara PRIVATE "${library_root}/proc/windows.c")
  elseif(DEFINED PLATFORM_LINUX)
    target_sources(thirdparty_yara PRIVATE "${library_root}/proc/linux.c")
  elseif(DEFINED PLATFORM_MACOS)
    target_sources(thirdparty_yara PRIVATE "${library_root}/proc/mach.c")
  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  # todo(alessandro): macOS and Windows support
  target_compile_definitions(thirdparty_yara PRIVATE
    PACKAGE_NAME=\"yara\"
    PACKAGE_TARNAME=\"yara\"
    PACKAGE_VERSION=\"3.10.0\"
    PACKAGE_STRING=\"yara\ 3.10.0\"
    PACKAGE_BUGREPORT=\"vmalvarez@virustotal.com\"
    PACKAGE_URL=\"\"
    PACKAGE=\"yara\"
    VERSION=\"3.10.0\"
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
    HAVE_LIBM=1
    HAVE_MEMMEM=1
    HAVE_TIMEGM=1
    HAVE_STDBOOL_H=1
    HAVE_CLOCK_GETTIME=1
    HAVE_SCAN_PROC_IMPL=1
    USE_LINUX_PROC
    HAVE_LIBCRYPTO=1
  )

  target_link_libraries(thirdparty_yara PUBLIC
    thirdparty_openssl
    thirdparty_libmagic
  )

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

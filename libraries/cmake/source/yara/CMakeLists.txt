# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(yaraMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/libyara")

  add_library(thirdparty_yara_strutils OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/strutils.cpp"
  )

  target_link_libraries(thirdparty_yara_strutils PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_yara_strutils PRIVATE
    "${library_root}/include"
    "${library_root}"
  )

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

    $<TARGET_OBJECTS:thirdparty_yara_strutils>
  )

  set(yara_strutils_definitions
    "xtoi=yara_strutils_xtoi"
    "strnlen_w=yara_strutils_strnlen_w"
    "strlcpy_w=yara_strutils_strlcpy_w"
    "strcmp_w=yara_strutils_strcmp_w"
    "strlcpy=yara_strutils_strlcpy"
    "strlcat=yara_strutils_strlcat"
    "memmem=yara_strutils_memmem"
    "yr_isalnum=yara_strutils_isalnum"
  )

  set_source_files_properties(
    "${library_root}/grammar.c"
    "${library_root}/hex_lexer.c"
    "${library_root}/lexer.c"
    "${library_root}/modules/pe/pe.c"
    "${library_root}/modules/dotnet/dotnet.c"
    "${library_root}/re_lexer.c"
    "${library_root}/parser.c"
    "${library_root}/sizedstr.c"
    "${library_root}/exec.c"
    "${library_root}/re.c"
    "${library_root}/scan.c"

    PROPERTIES COMPILE_DEFINITIONS
      "${yara_strutils_definitions}"
  )

  if(PLATFORM_WINDOWS)
    target_sources(thirdparty_yara PRIVATE
      "${library_root}/proc/windows.c"
    )

  elseif(PLATFORM_LINUX)
    target_sources(thirdparty_yara PRIVATE
      "${library_root}/proc/linux.c"
      "${library_root}/modules/magic/magic.c"
    )

  elseif(PLATFORM_MACOS)
    target_sources(thirdparty_yara PRIVATE
      "${library_root}/proc/mach.c"
      "${library_root}/modules/magic/magic.c"
      "${library_root}/modules/macho/macho.c"
    )

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  target_compile_definitions(thirdparty_yara PRIVATE
    HAVE_STDBOOL_H=1
    HAVE_CLOCK_GETTIME=1
    HAVE_LIBCRYPTO=1
  )

  target_link_libraries(thirdparty_yara
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_openssl
  )

  if(PLATFORM_POSIX)
    target_link_libraries(thirdparty_yara PUBLIC
      thirdparty_libmagic
    )
  endif()

  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_LINUX_PROC
      HAVE_TIMEGM=1
    )

  elseif(PLATFORM_MACOS)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_MACH_PROC
      HAVE_TIMEGM=1
      MACHO_MODULE
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_yara PRIVATE
      USE_WINDOWS_PROC
      HAVE_TIMEGM=0
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

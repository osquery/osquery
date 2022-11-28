# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libxml2Main)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libxml2
    "${library_root}/buf.c"
    "${library_root}/c14n.c"
    "${library_root}/catalog.c"
    "${library_root}/chvalid.c"
    "${library_root}/debugXML.c"
    "${library_root}/dict.c"
    "${library_root}/encoding.c"
    "${library_root}/entities.c"
    "${library_root}/error.c"
    "${library_root}/globals.c"
    "${library_root}/hash.c"
    "${library_root}/HTMLparser.c"
    "${library_root}/HTMLtree.c"
    "${library_root}/legacy.c"
    "${library_root}/list.c"
    "${library_root}/nanoftp.c"
    "${library_root}/nanohttp.c"
    "${library_root}/parser.c"
    "${library_root}/parserInternals.c"
    "${library_root}/pattern.c"
    "${library_root}/relaxng.c"
    "${library_root}/SAX2.c"
    "${library_root}/SAX.c"
    "${library_root}/schematron.c"
    "${library_root}/threads.c"
    "${library_root}/tree.c"
    "${library_root}/uri.c"
    "${library_root}/valid.c"
    "${library_root}/xlink.c"
    "${library_root}/xmlIO.c"
    "${library_root}/xmlmemory.c"
    "${library_root}/xmlmodule.c"
    "${library_root}/xmlreader.c"
    "${library_root}/xmlregexp.c"
    "${library_root}/xmlsave.c"
    "${library_root}/xmlschemas.c"
    "${library_root}/xmlschemastypes.c"
    "${library_root}/xmlstring.c"
    "${library_root}/xmlunicode.c"
    "${library_root}/xmlwriter.c"
    "${library_root}/xpath.c"
    "${library_root}/xpointer.c"
    "${library_root}/xzlib.c"
  )

  target_compile_definitions(thirdparty_libxml2
    PRIVATE
      _REENTRANT

    INTERFACE
      LIBXML_STATIC
  )

  if(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_libxml2 PRIVATE
      HAVE_WIN32_THREADS
    )
  endif()

  find_package(Threads REQUIRED)
  target_link_libraries(thirdparty_libxml2
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_zlib
      Threads::Threads
      ${CMAKE_DL_LIBS}
  )

  if(PLATFORM_POSIX)
    target_link_libraries(thirdparty_libxml2 PUBLIC
      m
    )
  endif()

  if(PLATFORM_LINUX)
    set(include_path_list
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/config/linux/${TARGET_PROCESSOR}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/version/linux/${TARGET_PROCESSOR}"
    )

  elseif(PLATFORM_WINDOWS)
    set(include_path_list
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/config/windows/${TARGET_PROCESSOR}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/version/windows/${TARGET_PROCESSOR}"
    )

  elseif(PLATFORM_MACOS)
    set(include_path_list
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/config/macos/${TARGET_PROCESSOR}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated/version/macos/${TARGET_PROCESSOR}"
    )

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  list(APPEND include_path_list
    "${library_root}"
    "${library_root}/include"
  )

  target_include_directories(thirdparty_libxml2 PRIVATE
    ${include_path_list}
  )

  target_include_directories(thirdparty_libxml2 SYSTEM INTERFACE
    ${include_path_list}
  )
endfunction()

libxml2Main()

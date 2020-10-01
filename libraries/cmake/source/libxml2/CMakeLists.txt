# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libxml2Main)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(library_srcs
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
    "${library_root}/parser.c"
    "${library_root}/parserInternals.c"
    "${library_root}/pattern.c"
    "${library_root}/relaxng.c"
    "${library_root}/SAX.c"
    "${library_root}/SAX2.c"
    "${library_root}/threads.c"
    "${library_root}/tree.c"
    "${library_root}/uri.c"
    "${library_root}/valid.c"
    "${library_root}/xinclude.c"
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

  if(DEFINED PLATFORM_POSIX)
    list(APPEND library_srcs
      "${library_root}/buf.c"
    )
  endif()

  add_library(thirdparty_libxml2
    ${library_srcs}
  )

  target_compile_definitions(thirdparty_libxml2 PUBLIC
    _REENTRANT
    LIBXML_STATIC
  )

  if(DEFINED PLATFORM_POSIX)
    target_compile_definitions(thirdparty_libxml2 PRIVATE
      HAVE_CONFIG_H
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_libxml2 PRIVATE
      _CRT_NONSTDC_NO_DEPRECATE
      _CRT_SECURE_NO_DEPRECATE
      _WINDOWS
      _MBCS
    )
    
    target_compile_definitions(thirdparty_libxml2 PUBLIC
      HAVE_WIN32_THREADS
    )
  endif()

  target_link_libraries(thirdparty_libxml2 PRIVATE
    thirdparty_c_settings
  )

  target_link_libraries(thirdparty_libxml2 PUBLIC
    thirdparty_icu
    thirdparty_zlib
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_include_directories(thirdparty_libxml2 SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/version/windows"
    )

    target_include_directories(thirdparty_libxml2 PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows"
      "${CMAKE_CURRENT_SOURCE_DIR}/version/windows"
    )
  else()
    target_include_directories(thirdparty_libxml2 SYSTEM INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/version/posix"
    )

    target_include_directories(thirdparty_libxml2 PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/posix"
      "${CMAKE_CURRENT_SOURCE_DIR}/version/posix"
    )
  endif()

  target_include_directories(thirdparty_libxml2 PRIVATE
    "${library_root}"
    "${library_root}/include"
  )

  target_include_directories(thirdparty_libxml2 SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

libxml2Main()

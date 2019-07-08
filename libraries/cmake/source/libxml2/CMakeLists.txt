# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libxml2Main)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libxml2
    "${library_root}/SAX.c"
    "${library_root}/entities.c"
    "${library_root}/encoding.c"
    "${library_root}/error.c"
    "${library_root}/parserInternals.c"
    "${library_root}/parser.c"
    "${library_root}/tree.c"
    "${library_root}/hash.c"
    "${library_root}/list.c"
    "${library_root}/xmlIO.c"
    "${library_root}/xmlmemory.c"
    "${library_root}/uri.c"
    "${library_root}/valid.c"
    "${library_root}/xlink.c"
    "${library_root}/HTMLparser.c"
    "${library_root}/HTMLtree.c"
    "${library_root}/debugXML.c"
    "${library_root}/xpath.c"
    "${library_root}/xpointer.c"
    "${library_root}/xinclude.c"
    "${library_root}/catalog.c"
    "${library_root}/globals.c"
    "${library_root}/threads.c"
    "${library_root}/c14n.c"
    "${library_root}/xmlstring.c"
    "${library_root}/buf.c"
    "${library_root}/xmlregexp.c"
    "${library_root}/xmlschemas.c"
    "${library_root}/xmlschemastypes.c"
    "${library_root}/xmlunicode.c"
    "${library_root}/xmlreader.c"
    "${library_root}/relaxng.c"
    "${library_root}/dict.c"
    "${library_root}/SAX2.c"
    "${library_root}/xmlwriter.c"
    "${library_root}/legacy.c"
    "${library_root}/chvalid.c"
    "${library_root}/pattern.c"
    "${library_root}/xmlsave.c"
    "${library_root}/xmlmodule.c"
    "${library_root}/xzlib.c"
  )

  target_compile_definitions(thirdparty_libxml2 PRIVATE
    HAVE_CONFIG_H
    _REENTRANT
  )

  target_compile_options(thirdparty_libxml2 PRIVATE
    -include config.h
  )

  target_link_libraries(thirdparty_libxml2 PUBLIC
    thirdparty_lzma
    thirdparty_zlib
  )

  target_link_libraries(thirdparty_libxml2 PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libxml2 PRIVATE
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${CMAKE_CURRENT_SOURCE_DIR}/version"
    "${library_root}/include"
  )

  target_include_directories(thirdparty_libxml2 SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/version"
    "${library_root}/include"
  )
endfunction()

libxml2Main()

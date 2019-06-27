# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExtensionsThriftMain)
  generateOsqueryExtensionsThriftOsquerycpp2()
endfunction()

function(generateOsqueryExtensionsThriftOsquerycpp2)
  add_osquery_library(osquery_extensions_thrift_osquerycpp2 EXCLUDE_FROM_ALL
    gen/Extension.cpp
    gen/ExtensionManager.cpp
    gen/osquery_constants.cpp
    gen/osquery_types.cpp
  )

  target_link_libraries(osquery_extensions_thrift_osquerycpp2 PUBLIC
    global_cxx_settings
    thirdparty_thrift
  )

  set(public_header_files
    gen/Extension.h
    gen/ExtensionManager.h
    gen/osquery_constants.h
    gen/osquery_types.h
  )

  generateIncludeNamespace(osquery_extensions_thrift_osquerycpp2 "" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryExtensionsThriftMain()

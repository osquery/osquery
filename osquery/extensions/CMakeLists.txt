# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExtensionsMain)
  add_subdirectory("thrift")

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryExtensions()
  generateOsqueryExtensionsImplthrift()
  generateOsqueryExtensionsExtensionsinterface()
endfunction()

function(generateOsqueryExtensions)
  add_osquery_library(osquery_extensions EXCLUDE_FROM_ALL extensions.cpp)

  enableLinkWholeArchive(osquery_extensions)

  target_link_libraries(osquery_extensions PUBLIC
    global_cxx_settings
    osquery_extensions_extensionsinterface
    osquery_core
    osquery_process
    osquery_utils
    osquery_utils_conversions
  )

  add_test(NAME osquery_extensions_extensiontests-test COMMAND osquery_extensions_extensiontests-test)
endfunction()

function(generateOsqueryExtensionsImplthrift)
  add_osquery_library(osquery_extensions_implthrift EXCLUDE_FROM_ALL impl_thrift.cpp)

  enableLinkWholeArchive(osquery_extensions_implthrift)

  if(DEFINED PLATFORM_FREEBSD)
    target_link_options(osquery_extensions_implthrift PUBLIC -lthrift)
  endif()

  target_link_libraries(osquery_extensions_implthrift PUBLIC
    global_cxx_settings
    osquery_extensions_extensionsinterface
    osquery_core
    osquery_extensions_thrift_osquerycpp2
    osquery_process
    osquery_utils
    osquery_utils_conversions
  )
endfunction()

function(generateOsqueryExtensionsExtensionsinterface)
  add_osquery_library(osquery_extensions_extensionsinterface EXCLUDE_FROM_ALL interface.cpp)

  set(public_header_files
    interface.h
  )

  target_link_libraries(osquery_extensions_extensionsinterface PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_filesystem
  )

  generateIncludeNamespace(osquery_extensions_extensionsinterface "osquery/extensions" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryExtensionsMain()

# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExtensionsMain)
  add_subdirectory("thrift")

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryExtensions()
  generateOsqueryExtensionsExtensionsservice()
endfunction()

function(generateOsqueryExtensions)
  add_osquery_library(osquery_extensions EXCLUDE_FROM_ALL
    extensions.cpp
    interface.cpp
    impl_thrift.cpp
  )

  if(DEFINED PLATFORM_FREEBSD)
    target_link_options(osquery_extensions PUBLIC
      -lthrift
    )
  endif()

  target_link_libraries(osquery_extensions PUBLIC
    osquery_cxx_settings
    osquery_headers
  )

  target_link_libraries(osquery_extensions PRIVATE
    osquery_extensions_thrift_osquerycpp2
    osquery_process
    osquery_logger
    osquery_filesystem
    osquery_registry
    osquery_utils
  )

  set(public_header_files
    interface.h
  )

  generateIncludeNamespace(osquery_extensions "osquery/extensions" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_extensions_extensiontests-test COMMAND osquery_extensions_extensiontests-test)
endfunction()

function(generateOsqueryExtensionsExtensionsservice)
  add_osquery_library(osquery_extensions_service EXCLUDE_FROM_ALL
    service.cpp
    impl_service.cpp
  )

  set(public_header_files
    service.h
  )

  target_link_libraries(osquery_extensions_service PUBLIC
    osquery_cxx_settings
    osquery_headers
    osquery_dispatcher
    osquery_extensions
    osquery_utils
  )

  target_link_libraries(osquery_extensions_service PRIVATE
    osquery_core
    osquery_logger
    osquery_filesystem
    osquery_core_init
    thirdparty_boost
  )

  generateIncludeNamespace(osquery_extensions_service "osquery/extensions" "FILE_ONLY" ${public_header_files})
endfunction()


osqueryExtensionsMain()

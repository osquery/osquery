# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRegistryMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryRegistry()
endfunction()

function(generateOsqueryRegistry)
  add_osquery_library(osquery_registry EXCLUDE_FROM_ALL
    registry_factory.cpp
    registry_interface.cpp
  )

  target_link_libraries(osquery_registry PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_process
    osquery_extensions
    osquery_utils_conversions
    osquery_utils_system_env
    thirdparty_boost
  )

  set(public_header_files
    registry.h
    registry_factory.h
    registry_interface.h
  )

  generateIncludeNamespace(osquery_registry "osquery/registry" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_registry_tests-test COMMAND osquery_registry_tests-test)
endfunction()

osqueryRegistryMain()

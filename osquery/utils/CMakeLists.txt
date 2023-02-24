# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsMain)
  if(OSQUERY_BUILD_AWS)
    add_subdirectory("aws")
  endif()

  add_subdirectory("azure")
  add_subdirectory("caches")
  add_subdirectory("system")
  add_subdirectory("status")
  add_subdirectory("json")
  add_subdirectory("macros")
  add_subdirectory("pidfile")
  add_subdirectory("config")
  add_subdirectory("info")
  add_subdirectory("error")
  add_subdirectory("debug")
  add_subdirectory("expected")
  add_subdirectory("conversions")
  add_subdirectory("versioning")
  add_subdirectory("schemer")
  add_subdirectory("ycloud")

  if(DEFINED PLATFORM_LINUX)
    add_subdirectory("linux")
  endif()

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryUtilsUtilstestsTest()
  endif()

  generateOsqueryUtils()
endfunction()

function(generateOsqueryUtils)
  set(source_files
    base64.cpp
    chars.cpp
    only_movable.cpp
    rot13.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/plist.mm
    )
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/shellitem.cpp
      windows/lzxpress.cpp
      windows/shelllnk.cpp
    )
  endif()

  add_osquery_library(osquery_utils EXCLUDE_FROM_ALL
    ${source_files}
  )

  add_osquery_library(osquery_utils_attribute INTERFACE)

  target_link_libraries(osquery_utils PUBLIC
    osquery_cxx_settings
    thirdparty_glog
    osquery_logger
    osquery_utils_config
    osquery_utils_conversions
    osquery_utils_expected
    osquery_utils_info
    osquery_utils_status
    thirdparty_boost
  )

  set(public_header_files
    attribute.h
    base64.h
    chars.h
    enum_class_hash.h
    map_take.h
    mutex.h
    only_movable.h
    rot13.h
    scope_guard.h
  )

  generateIncludeNamespace(osquery_utils "osquery/utils" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_MACOS)
    set(platform_public_header_files
      darwin/plist.h
      darwin/iokit_helpers.h
    )

    generateIncludeNamespace(osquery_utils "osquery/utils" "FULL_PATH" ${platform_public_header_files})
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    set(platform_public_header_files
      windows/shellitem.h
      windows/lzxpress.h
      windows/shelllnk.h
    )

    generateIncludeNamespace(osquery_utils "osquery/utils" "FULL_PATH" ${platform_public_header_files})
  endif()

  set(attribute_public_header_files
    attribute.h
  )

  generateIncludeNamespace(osquery_utils_attribute "osquery/utils" "FILE_ONLY" ${attribute_public_header_files})

  add_test(NAME osquery_utils_utilstests-test COMMAND osquery_utils_utilstests-test)

endfunction()

function(generateOsqueryUtilsUtilstestsTest)
  set(source_files
    tests/base64.cpp
    tests/chars.cpp
    tests/map_take.cpp
    tests/rot13.cpp
    tests/scope_guard.cpp
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      tests/windows/env.cpp
      tests/windows/filetime.cpp
      tests/windows/shellitems.cpp
      tests/windows/shelllnk.cpp
    )
  endif()

  add_osquery_executable(osquery_utils_utilstests-test ${source_files})

  target_link_libraries(osquery_utils_utilstests-test PRIVATE
    osquery_cxx_settings
    osquery_utils
    osquery_utils_system_env
    thirdparty_googletest
  )
endfunction()

osqueryUtilsMain()

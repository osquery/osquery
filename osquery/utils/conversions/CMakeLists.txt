# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsConversionsMain)
  if(OSQUERY_BUILD_TESTS)
    generateOsqueryUtilsConversionsConversionstestsTest()
    generateOsqueryUtilsConversionsTotestsTest()
  endif()

  generateOsqueryUtilsConversions()
  generateOsqueryUtilsConversionsTo()
endfunction()

function(generateOsqueryUtilsConversions)
  set(source_files
    split.cpp
    tryto.cpp
    trim.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/cfdata.cpp
      darwin/cfdictionary.cpp
      darwin/cfnumber.cpp
      darwin/cfstring.cpp
      darwin/cftime.cpp
      darwin/iokit.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/strings.cpp
      windows/windows_time.cpp
    )
  endif()

  add_osquery_library(osquery_utils_conversions EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_utils_conversions PUBLIC
    osquery_cxx_settings
    osquery_utils
    osquery_utils_system_systemutils
    osquery_logger
    osquery_utils_conversions_to
    osquery_utils_expected
    thirdparty_boost
    thirdparty_glog
  )

  set(public_header_files
    castvariant.h
    join.h
    split.h
    tryto.h
    trim.h
  )

  generateIncludeNamespace(osquery_utils_conversions "osquery/utils/conversions" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_MACOS)
    set(platform_public_header_files
      darwin/cfdata.h
      darwin/cfdictionary.h
      darwin/cfnumber.h
      darwin/cfstring.h
      darwin/cftime.h
      darwin/iokit.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_public_header_files
      windows/strings.h
      windows/windows_time.h
    )
  endif()

  list(LENGTH platform_public_header_files platform_public_header_files_size)

  if(${platform_public_header_files_size} GREATER 0)
    generateIncludeNamespace(osquery_utils_conversions "osquery/utils/conversions" "FULL_PATH" ${platform_public_header_files})
  endif()

  add_test(NAME osquery_utils_conversions_conversionstests-test COMMAND osquery_utils_conversions_conversionstests-test)
endfunction()

function(generateOsqueryUtilsConversionsTo)
  add_osquery_library(osquery_utils_conversions_to INTERFACE)

  set(public_header_files
    to.h
  )

  target_link_libraries(osquery_utils_conversions_to INTERFACE thirdparty_boost)

  generateIncludeNamespace(osquery_utils_conversions_to "osquery/utils/conversions" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_conversions_totests-test COMMAND osquery_utils_conversions_totests-test)
endfunction()

function(generateOsqueryUtilsConversionsConversionstestsTest)
  set(source_files
    tests/join.cpp
    tests/split.cpp
    tests/tryto.cpp
    tests/trim.cpp
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/tests/cfstring.cpp
      darwin/tests/cfdictionary.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/tests/strings.cpp
      windows/tests/windows_time.cpp
    )
  endif()

  add_osquery_executable(osquery_utils_conversions_conversionstests-test ${source_files})

  target_link_libraries(osquery_utils_conversions_conversionstests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_conversions
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryUtilsConversionsTotestsTest)
  add_osquery_executable(osquery_utils_conversions_totests-test tests/to.cpp)

  target_link_libraries(osquery_utils_conversions_totests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_conversions_to
    thirdparty_googletest
  )
endfunction()

osqueryUtilsConversionsMain()

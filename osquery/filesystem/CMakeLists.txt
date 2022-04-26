# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryFilesystemMain)

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryFilesystemTest()
  endif()

  generateOsqueryFilesystem()
  generateOsqueryFilesystemMockfilestructure()
endfunction()

function(generateOsqueryFilesystem)
  set(source_files
    file_compression.cpp
    filesystem.cpp
  )

  set(public_header_files
    fileops.h
    filesystem.h
  )

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/bsd_file_flags.cpp
    )
  endif()

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/fileops.cpp
      posix/xattrs.cpp
    )

    list(APPEND public_header_files
      posix/xattrs.h
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/mem.cpp
      linux/proc.cpp
      linux/mounts.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/fileops.cpp
    )
  endif()

  add_osquery_library(osquery_filesystem EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_filesystem PUBLIC
    osquery_cxx_settings
    osquery_process
    osquery_sql
    osquery_utils_conversions
    osquery_utils_status
    osquery_utils_system_env
    osquery_utils_system_filepath
    thirdparty_boost
    thirdparty_libarchive
    thirdparty_zstd
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_filesystem PUBLIC
      osquery_utils_system_usersgroupshelpers
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND public_header_files
      linux/proc.h
      linux/mounts.h
    )
  endif()

  generateIncludeNamespace(osquery_filesystem "osquery/filesystem" "FULL_PATH" ${public_header_files})

  add_test(NAME osquery_filesystem_filesystemtests-test COMMAND osquery_filesystem_filesystemtests-test)

  set_tests_properties(
    osquery_filesystem_filesystemtests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

function(generateOsqueryFilesystemMockfilestructure)
  add_osquery_library(osquery_filesystem_mockfilestructure EXCLUDE_FROM_ALL
    mock_file_structure.cpp
  )

  target_link_libraries(osquery_filesystem_mockfilestructure PUBLIC
    osquery_cxx_settings
    thirdparty_boost
    osquery_filesystem
  )

  set(public_header_files
    mock_file_structure.h
  )

  generateIncludeNamespace(osquery_filesystem_mockfilestructure "osquery/filesystem" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryFilesystemTest)

  set(source_files
    tests/fileops.cpp
    tests/filesystem.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      tests/posix/xattrs.cpp
    )
  endif()

  if(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      tests/darwin/plist_tests.cpp
      tests/darwin/bsd_file_flags_tests.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      tests/linux/proc_tests.cpp
    )
  endif()

  add_osquery_executable(osquery_filesystem_filesystemtests-test ${source_files})

  target_link_libraries(osquery_filesystem_filesystemtests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_extensions
    osquery_extensions_implthrift
    osquery_process
    osquery_registry
    osquery_filesystem_mockfilestructure
    osquery_filesystem
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryFilesystemMain()

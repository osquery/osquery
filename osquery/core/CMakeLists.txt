# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryCoreMain)
  add_subdirectory("plugins")
  add_subdirectory("sql")

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryCore()
  generateOsqueryCoreInit()
endfunction()

function(generateOsqueryCoreInit)
  set(source_files
    init.cpp
    watcher.cpp
  )

  add_osquery_library(osquery_core_init EXCLUDE_FROM_ALL
    ${source_files}
  )

  set(dependencies
    osquery_cxx_settings
    osquery_config
    osquery_core
    osquery_numericmonitoring
    osquery_extensions
    osquery_distributed
    osquery_utils_pidfile
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND dependencies
      osquery_system_usersgroups_services
    )
  endif()

  target_link_libraries(osquery_core_init PUBLIC
    osquery_cxx_settings

    ${dependencies}
  )

  set(public_header_files
    watcher.h
  )

  generateIncludeNamespace(osquery_core_init "osquery/core" "FILE_ONLY" ${public_header_files})

  # TODO: This test should actually run as root, but it's currently broken when using that user
  if(DEFINED PLATFORM_POSIX)
    add_test(NAME osquery_core_tests_permissionstests-test COMMAND osquery_core_tests_permissionstests-test)
  endif()

  add_test(NAME osquery_core_tests_watchertests-test COMMAND osquery_core_tests_watchertests-test)

endfunction()

function(generateOsqueryCore)
  set(source_files
    flags.cpp
    query.cpp
    shutdown.cpp
    system.cpp
    tables.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/platform.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/handle.cpp
      windows/platform.cpp
      windows/wmi.cpp
      windows/global_users_groups_cache.cpp
    )
  endif()

  add_osquery_library(osquery_core EXCLUDE_FROM_ALL
    ${source_files}
  )

  set(dependencies
    osquery_cxx_settings
    osquery_core_plugins
    osquery_core_sql
    osquery_filesystem
    osquery_process
    osquery_registry
    osquery_utils
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_env
    osquery_utils_system_systemutils
    osquery_utils_system_time
    osquery_logger
    thirdparty_gflags
    thirdparty_glog
    thirdparty_openssl
    thirdparty_sqlite
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND dependencies
      osquery_system_usersgroups_caches
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies thirdparty_util-linux)
  endif()

  target_link_libraries(osquery_core PUBLIC
    osquery_cxx_settings

    ${dependencies}
  )

  set(public_header_files
    core.h
    flags.h
    flagalias.h
    query.h
    tables.h
    shutdown.h
    system.h
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND public_header_files
      windows/handle.h
      windows/ntapi.h
      windows/wmi.h
      windows/global_users_groups_cache.h
    )
  endif()

  generateIncludeNamespace(osquery_core "osquery/core" "FULL_PATH" ${public_header_files})

  add_test(NAME osquery_core_tests_flagstests-test COMMAND osquery_core_tests_flagstests-test)
  add_test(NAME osquery_core_tests_systemtests-test COMMAND osquery_core_tests_systemtests-test)
  add_test(NAME osquery_core_tests_tablestests-test COMMAND osquery_core_tests_tablestests-test)
  add_test(NAME osquery_core_tests_querytests-test COMMAND osquery_core_tests_querytests-test)
  add_test(NAME osquery_core_tests_processtests-test COMMAND osquery_core_tests_processtests-test)

  if(DEFINED PLATFORM_WINDOWS)
    add_test(NAME osquery_core_tests_wmitests-test COMMAND osquery_core_tests_wmitests-test)
  endif()
endfunction()

osqueryCoreMain()

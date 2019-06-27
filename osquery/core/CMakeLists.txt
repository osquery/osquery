# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryCoreMain)
  add_subdirectory("plugins")
  add_subdirectory("sql")

  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()

  generateOsqueryCore()
endfunction()

function(generateOsqueryCore)
  set(source_files
    flags.cpp
    init.cpp
    query.cpp
    system.cpp
    tables.cpp
    watcher.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/initializer.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/handle.cpp
      windows/initializer.cpp
      windows/wmi.cpp
    )
  endif()

  add_osquery_library(osquery_core EXCLUDE_FROM_ALL
    ${source_files}
  )

  set(dependencies
    osquery_headers
    osquery_config
    osquery_core_plugins
    osquery_core_sql
    osquery_filesystem
    osquery_process
    osquery_utils
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_env
    osquery_utils_system_systemutils
    osquery_utils_system_time
    osquery_logger
    osquery_extensions
    thirdparty_gflags
    thirdparty_glog
    thirdparty_openssl
    thirdparty_sqlite
    thirdparty_glibc_pthread
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND dependencies thirdparty_util-linux)
  endif()

  target_link_libraries(osquery_core PUBLIC
    global_cxx_settings

    ${dependencies}
  )

  set(public_header_files
    watcher.h
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND windows_public_header_files
      windows/handle.h
      windows/ntapi.h
      windows/wmi.h
    )

    generateIncludeNamespace(osquery_core "osquery/core" "FULL_PATH" ${windows_public_header_files})
  endif()

  generateIncludeNamespace(osquery_core "osquery/core" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_core_tests_flagstests-test COMMAND osquery_core_tests_flagstests-test)
  add_test(NAME osquery_core_tests_systemtests-test COMMAND osquery_core_tests_systemtests-test)
  add_test(NAME osquery_core_tests_tablestests-test COMMAND osquery_core_tests_tablestests-test)
  add_test(NAME osquery_core_tests_watcherpermissionstests-test COMMAND osquery_core_tests_watcherpermissionstests-test)
  add_test(NAME osquery_core_tests_querytests-test COMMAND osquery_core_tests_querytests-test)

endfunction()

osqueryCoreMain()

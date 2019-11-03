# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

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

  target_link_libraries(osquery_core_init PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_config
  )

  set(public_header_files
    watcher.h
    init.h
  )

  generateIncludeNamespace(osquery_core_init "osquery/core" "FULL_PATH" ${public_header_files})
endfunction()

function(generateOsqueryCore)
  set(source_files
    flags.cpp
    query.cpp
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
      windows/wmi.cpp
      windows/platform.cpp
    )
  endif()

  add_osquery_library(osquery_core EXCLUDE_FROM_ALL
    ${source_files}
  )

  set(public_dependencies
    osquery_headers
    osquery_core_plugins
    osquery_core_sql
    osquery_utils
    thirdparty_gflags
    thirdparty_glog
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND public_dependencies thirdparty_util-linux)
  endif()

  target_link_libraries(osquery_core PUBLIC
    osquery_cxx_settings
    ${public_dependencies}
  )

  target_link_libraries(osquery_core PRIVATE
    osquery_config
    osquery_filesystem
    osquery_process
    osquery_registry
    osquery_utils
    osquery_utils_system
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND windows_public_header_files
      windows/handle.h
      windows/ntapi.h
      windows/wmi.h
    )

    generateIncludeNamespace(osquery_core "osquery/core" "FULL_PATH" ${windows_public_header_files})
  endif()

  add_test(NAME osquery_core_tests_flagstests-test COMMAND osquery_core_tests_flagstests-test)
  add_test(NAME osquery_core_tests_systemtests-test COMMAND osquery_core_tests_systemtests-test)
  add_test(NAME osquery_core_tests_tablestests-test COMMAND osquery_core_tests_tablestests-test)
  add_test(NAME osquery_core_tests_watcherpermissionstests-test COMMAND osquery_core_tests_watcherpermissionstests-test)
  add_test(NAME osquery_core_tests_querytests-test COMMAND osquery_core_tests_querytests-test)
  add_test(NAME osquery_core_tests_processtests-test COMMAND osquery_core_tests_processtests-test)

endfunction()

osqueryCoreMain()

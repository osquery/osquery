# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSystemMain)

  add_subdirectory("linux")

  if(BUILD_TESTING)
    generateOsqueryUtilsSystemErrnoErrnotestsTest()
    generateOsqueryUtilsSystemCpuCputopologytestsTest()
    generateOsqueryUtilsSystemTimeTimetestsTest()
  endif()

  generateOsqueryUtilsSystemEnv()
  generateOsqueryUtilsSystemFilepath()
  generateOsqueryUtilsSystemErrno()
  generateOsqueryUtilsSystemCputopology()
  generateOsqueryUtilsSystemTime()
  generateOsqueryUtilsSystem()
  generateOsqueryUtilsSystemUptime()
endfunction()

function(generateOsqueryUtilsSystemEnv)
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/env.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/env.cpp
    )
  else()
    return()
  endif()

  add_osquery_library(osquery_utils_system_env EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_utils_system_env PUBLIC
    global_cxx_settings
    thirdparty_boost
  )

  set(public_header_files
    env.h
  )

  generateIncludeNamespace(osquery_utils_system_env "osquery/utils/system" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryUtilsSystemFilepath)

  if(DEFINED PLATFORM_WINDOWS)
    add_osquery_library(osquery_utils_system_filepath INTERFACE)
  else()
    add_osquery_library(osquery_utils_system_filepath EXCLUDE_FROM_ALL
      posix/filepath.cpp
    )

    set(public_header_files
        filepath.h
    )

    generateIncludeNamespace(osquery_utils_system_filepath "osquery/utils/system" "FILE_ONLY" ${public_header_files})

    target_link_libraries(osquery_utils_system_filepath PUBLIC
      global_cxx_settings
    )
  endif()

endfunction()

function(generateOsqueryUtilsSystemErrno)
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/errno.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/errno.cpp
    )
  else()
    return()
  endif()

  add_osquery_library(osquery_utils_system_errno EXCLUDE_FROM_ALL
    ${source_files}
  ) 

  target_link_libraries(osquery_utils_system_errno PUBLIC
    global_cxx_settings
  )

  set(public_header_files
    errno.h
  )

  if(DEFINED PLATFORM_POSIX)
      list(APPEND public_header_files
        posix/errno.h
      )
  endif()

  generateIncludeNamespace(osquery_utils_system_errno "osquery/utils/system" "FULL_PATH" ${public_header_files})

  add_test(NAME osquery_utils_system_errno_errnotests-test COMMAND osquery_utils_system_errno_errnotests-test)

endfunction()

function(generateOsqueryUtilsSystemCputopology)
  if(DEFINED PLATFORM_LINUX)
    add_osquery_library(osquery_utils_system_cputopology EXCLUDE_FROM_ALL
      linux/cpu.cpp
    )

    target_link_libraries(osquery_utils_system_cputopology PUBLIC
      global_cxx_settings
      osquery_utils_conversions
      osquery_utils_expected
      thirdparty_boost
    )

    set(public_header_files
      linux/cpu.h
    )

    generateIncludeNamespace(osquery_utils_system_cputopology "osquery/utils/system" "FULL_PATH" ${public_header_files})

    add_test(NAME osquery_utils_system_cputopologytests-test COMMAND osquery_utils_system_cputopologytests-test)

  else()
    add_osquery_library(osquery_utils_system_cputopology INTERFACE)
  endif()

endfunction()

function(generateOsqueryUtilsSystemTime)
  set(source_files
    time.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/time.cpp
    )
    
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/time.cpp
    )

  else()
    return()
  endif()

  add_osquery_library(osquery_utils_system_time EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_utils_system_time PUBLIC
    global_cxx_settings
    thirdparty_boost
  )

  set(public_header_files
    time.h
  )

  generateIncludeNamespace(osquery_utils_system_time "osquery/utils/system" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_utils_system_time_timetest-test COMMAND osquery_utils_system_time_timetest-test)

endfunction()

function(generateOsqueryUtilsSystem)
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/system.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/system.cpp
    )

  else()
    return()
  endif()

  add_osquery_library(osquery_utils_system_systemutils EXCLUDE_FROM_ALL
    ${source_files}
  ) 

  target_link_libraries(osquery_utils_system_systemutils PUBLIC
    global_cxx_settings
    osquery_utils_info
    thirdparty_boost
    thirdparty_googletest_headers
  )

  if(DEFINED PLATFORM_POSIX)
    set(public_header_files
      posix/system.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(public_header_files
      windows/system.h
    )
  endif()

  generateIncludeNamespace(osquery_utils_system_systemutils "osquery/utils/system" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryUtilsSystemUptime)
  add_osquery_library(osquery_utils_system_uptime EXCLUDE_FROM_ALL
    uptime.cpp
  ) 

  target_link_libraries(osquery_utils_system_uptime PUBLIC
    global_cxx_settings
    osquery_utils_system_systemutils
  )

  set(public_header_files
    uptime.h
  )

  generateIncludeNamespace(osquery_utils_system_uptime "osquery/utils/system" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryUtilsSystemErrnoErrnotestsTest)

  set(source_files
    tests/errno.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files posix/tests/errno.cpp)
  endif()

  add_osquery_executable(osquery_utils_system_errno_errnotests-test ${source_files})

  target_link_libraries(osquery_utils_system_errno_errnotests-test PRIVATE
    global_cxx_settings
    osquery_utils_system_errno
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryUtilsSystemCpuCputopologytestsTest)

  set(source_files
    tests/cpu.cpp
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files linux/tests/cpu.cpp)
  endif()

  add_osquery_executable(osquery_utils_system_cputopologytests-test ${source_files})

  target_link_libraries(osquery_utils_system_cputopologytests-test PRIVATE
    global_cxx_settings
    osquery_utils_system_cputopology
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryUtilsSystemTimeTimetestsTest)
  add_osquery_executable(osquery_utils_system_time_timetest-test tests/time.cpp)

  target_link_libraries(osquery_utils_system_time_timetest-test PRIVATE
    global_cxx_settings
    osquery_utils_system_time
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSystemMain()

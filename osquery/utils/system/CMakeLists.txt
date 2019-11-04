# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryUtilsSystemMain)

  add_subdirectory("linux")

  if(OSQUERY_BUILD_TESTS)
    generateOsqueryUtilsSystemTest()
  endif()

  generateOsqueryUtilsSystem()
endfunction()

function(generateOsqueryUtilsSystem)
  set(source_files
    time.cpp
    uptime.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/env.cpp
      posix/filepath.cpp
      posix/errno.cpp
      posix/time.cpp
      posix/system.cpp
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/env.cpp
      windows/errno.cpp
      windows/time.cpp
      windows/system.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/cpu.cpp
      linux/udev.cpp
    )
  endif()

  add_osquery_library(osquery_utils_system EXCLUDE_FROM_ALL
    ${source_files}
  )

  set(public_header_files
    filepath.h
    uptime.h
    time.h
    errno.h
    env.h
  )

  add_osquery_library(osquery_utils_system_linux INTERFACE)
  add_osquery_library(osquery_utils_system_posix INTERFACE)
  add_osquery_library(osquery_utils_system_windows INTERFACE)

  if(DEFINED PLATFORM_POSIX)
    set(posix_public_header_files
      posix/errno.h
      posix/system.h
    )

    generateIncludeNamespace(osquery_utils_system_posix "osquery/utils/system/posix" "FILE_ONLY" ${posix_public_header_files})
  elseif(DEFINED PLATFORM_WINDOWS)
    set(windows_public_header_files
      windows/system.h
    )

    generateIncludeNamespace(osquery_utils_system_windows "osquery/utils/system" "FILE_ONLY" ${windows_public_header_files})
  endif()

  if(DEFINED PLATFORM_LINUX)
    set(linux_public_header_files
      linux/udev.h
      linux/cpu.h
    )

    generateIncludeNamespace(osquery_utils_system_linux "osquery/utils/system/linux" "FILE_ONLY" ${linux_public_header_files})

    target_link_libraries(osquery_utils_system_linux INTERFACE
      thirdparty_libudev
    )
  endif()

  generateIncludeNamespace(osquery_utils_system "osquery/utils/system" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_utils_system PUBLIC
    osquery_cxx_settings
    osquery_utils
    osquery_utils_system_linux
    osquery_utils_system_posix
    osquery_utils_system_windows
    thirdparty_boost
    thirdparty_googletest_headers
  )

endfunction()

function(generateOsqueryUtilsSystemTest)

  set(source_files
    tests/errno.cpp
    tests/cpu.cpp
    tests/time.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/tests/errno.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/tests/cpu.cpp
    )
  endif()

  add_osquery_executable(osquery_utils_system-test ${source_files})

  target_link_libraries(osquery_utils_system-test PRIVATE
    osquery_cxx_settings
    osquery_utils_system
    thirdparty_googletest
  )
endfunction()

osqueryUtilsSystemMain()

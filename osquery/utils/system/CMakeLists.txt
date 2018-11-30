# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(osquery_utils_system_main)
  generateOsqueryUtilsSystemEnv()
  generateOsqueryUtilsSystemFilepath()
  generateOsqueryUtilsSystemErrno()
  generateOsqueryUtilsSystemCpu()
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

  add_library(osquery_utils_system_env EXCLUDE_FROM_ALL
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
  if(DEFINED PLATFORM_POSIX)
    set(source_files
      posix/filepath.cpp
    )
  else()
    return()
  endif()

  add_library(osquery_utils_system_filepath EXCLUDE_FROM_ALL
    ${source_files}
  ) 

  target_link_libraries(osquery_utils_system_filepath PUBLIC
    global_cxx_settings
  )

  set(public_header_files
    filepath.h
  )

  generateIncludeNamespace(osquery_utils_system_filepath "osquery/utils/system" "FILE_ONLY" ${public_header_files})
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

  add_library(osquery_utils_system_errno EXCLUDE_FROM_ALL
    ${source_files}
  ) 

  target_link_libraries(osquery_utils_system_errno PUBLIC
    global_cxx_settings
  )

  set(public_header_files
    errno.h
  )

  generateIncludeNamespace(osquery_utils_system_errno "osquery/utils/system" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryUtilsSystemCpu)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  add_library(osquery_utils_system_cpu EXCLUDE_FROM_ALL
    linux/cpu.cpp
  ) 

  target_link_libraries(osquery_utils_system_cpu PUBLIC
    global_cxx_settings
    osquery_utils_conversions
    osquery_utils_expected
    thirdparty_boost
  )

  set(public_header_files
    linux/cpu.h
  )

  generateIncludeNamespace(osquery_utils_system_cpu "osquery/utils/system" "FULL_PATH" ${public_header_files})
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

  add_library(osquery_utils_system_time EXCLUDE_FROM_ALL
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

  add_library(osquery_utils_system EXCLUDE_FROM_ALL
    ${source_files}
  ) 

  target_link_libraries(osquery_utils_system PUBLIC
    global_cxx_settings
    osquery_utils_info
    thirdparty_boost
    thirdparty_googletest
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

  generateIncludeNamespace(osquery_utils_system "osquery/utils/system" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryUtilsSystemUptime)
  add_library(osquery_utils_system_uptime EXCLUDE_FROM_ALL
    uptime.cpp
  ) 

  target_link_libraries(osquery_utils_system_uptime PUBLIC
    global_cxx_settings
    osquery_utils_system
  )

  set(public_header_files
    uptime.h
  )

  generateIncludeNamespace(osquery_utils_system_uptime "osquery/utils/system" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_utils_system_main()

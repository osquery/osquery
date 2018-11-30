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

function(osquery_filesystem_main)
  generateOsqueryFilesystem()
  generateOsqueryFilesystemMockfilestructure()
endfunction()

function(generateOsqueryFilesystem)
  set(source_files
    file_compression.cpp
    filesystem.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/fileops.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/mem.cpp
      linux/proc.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/fileops.cpp
    )
  endif()

  add_library(osquery_filesystem EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_filesystem PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_process
    osquery_utils_conversions
    osquery_utils_status
    osquery_utils_system_env
    thirdparty_boost
    thirdparty_libarchive
    thirdparty_zstd
  )

  set(public_header_files
    fileops.h
    filesystem.h
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND public_header_files
      linux/proc.h
    )
  endif()

  generateIncludeNamespace(osquery_filesystem "osquery/filesystem" "FULL_PATH" ${public_header_files})
endfunction()

function(generateOsqueryFilesystemMockfilestructure)
  add_library(osquery_filesystem_mockfilestructure EXCLUDE_FROM_ALL
    mock_file_structure.cpp
  )

  target_link_libraries(osquery_filesystem_mockfilestructure PUBLIC
    global_cxx_settings
    thirdparty_boost
    osquery_filesystem
  )

  set(public_header_files
    mock_file_structure.h
  )

  generateIncludeNamespace(osquery_filesystem_mockfilestructure "osquery/filesystem" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_filesystem_main()

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

function(osquery_tables_networking_main)
  generateOsqueryTablesNetworking()
endfunction()

function(generateOsqueryTablesNetworking)
  set(source_files
    curl.cpp
    curl_certificate.cpp
    etc_hosts.cpp
    etc_protocols.cpp
    etc_services.cpp
    listening_ports.cpp
  )
  
  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/dns_resolvers.cpp
      posix/interfaces.cpp
      posix/utils.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      linux/arp_cache.cpp
      linux/interface_ip.cpp
      linux/iptables.cpp
      linux/iptc_proxy.c
      linux/process_open_sockets.cpp
      linux/routes.cpp
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/interface_ip.cpp
      darwin/routes.cpp
      darwin/wifi.mm
      darwin/wifi_status.mm
      darwin/wifi_survey.mm
      darwin/wifi_utils.mm
    )

  elseif(DEFINED PLATFORM_FREEBSD)
    list(APPEND source_files
      freebsd/interface_ip.cpp
      freebsd/process_open_sockets.cpp
      freebsd/routes.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/arp_cache.cpp
      windows/interfaces.cpp
      windows/process_open_sockets.cpp
      windows/routes.cpp
    )
  endif()

  add_library(osquery_tables_networking EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_tables_networking PUBLIC
    global_cxx_settings
    osquery_core
    osquery_filesystem
    osquery_remote_httpclient
    osquery_utils
    osquery_utils_conversions
    osquery_tables_system
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND platform_deps
      thirdparty_libiptables
      thirdparty_libresolv
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND platform_deps
      thirdparty_libresolv
    )
  endif()

  target_link_libraries(osquery_tables_networking PUBLIC
    ${platform_deps}
  )

  if(DEFINED PLATFORM_POSIX)
    set(public_header_files
      posix/interfaces.h
      posix/utils.h
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND public_header_files
      linux/inet_diag.h
      linux/iptc_proxy.h
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND public_header_files
      darwin/wifi_utils.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND public_header_files
      windows/interfaces.h
    )
  endif()

  generateIncludeNamespace(osquery_tables_networking "osquery/tables/networking" "FULL_PATH" ${public_header_files})
endfunction()

osquery_tables_networking_main()

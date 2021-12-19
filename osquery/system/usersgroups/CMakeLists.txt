# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osquerySystemUsersGroupsMain)
  if(DEFINED PLATFORM_WINDOWS)
    generateOsquerySystemUsersGroupsWindowsCaches()
    generateOsquerySystemUsersGroupsWindowsServices()

    if(OSQUERY_BUILD_TESTS)
      add_subdirectory("windows/tests")
    endif()
  endif()
endfunction()

function(generateOsquerySystemUsersGroupsWindowsServices)

  add_osquery_library(osquery_system_usersgroups_services
    windows/users_service.cpp
    windows/groups_service.cpp
  )

  target_link_libraries(osquery_system_usersgroups_services
    PRIVATE
      osquery_cxx_settings
      osquery_dispatcher
      osquery_core
    PUBLIC
      osquery_system_usersgroups_caches
  )

  set(public_header_files
    windows/users_service.h
    windows/groups_service.h
  )

  generateIncludeNamespace(osquery_system_usersgroups_services "osquery/system/usersgroups" "FULL_PATH" ${public_header_files})

endfunction()

function(generateOsquerySystemUsersGroupsWindowsCaches)
  add_osquery_library(osquery_system_usersgroups_caches
    windows/users_groups_cache.cpp
  )

  target_link_libraries(osquery_system_usersgroups_caches
    PRIVATE
      osquery_cxx_settings
    PUBLIC
      osquery_utils_system_usersgroupshelpers
  )

  set(public_header_files
    windows/users_groups_cache.h
  )

  generateIncludeNamespace(osquery_system_usersgroups_caches "osquery/system/usersgroups" "FULL_PATH" ${public_header_files})
endfunction()

osquerySystemUsersGroupsMain()

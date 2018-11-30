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

function(osquery_database_plugins_main)
  generateOsqueryDatabasePluginsEphemeral()
  generateOsqueryDatabasePluginsRocksdb()
  generateOsqueryDatabasePluginsSqlite()
endfunction()

function(generateOsqueryDatabasePluginsEphemeral)
  add_library(osquery_database_plugins_ephemeral EXCLUDE_FROM_ALL
    ephemeral.cpp
  )

  enableLinkWholeArchive(osquery_database_plugins_ephemeral)

  target_link_libraries(osquery_database_plugins_ephemeral PUBLIC
    global_cxx_settings
    osquery_core
    osquery_database
    osquery_registry
    osquery_utils
  )

  set(public_header_files
    ephemeral.h
  )

  generateIncludeNamespace(osquery_database_plugins_ephemeral "osquery/database/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryDatabasePluginsRocksdb)
  add_library(osquery_database_plugins_rocksdb EXCLUDE_FROM_ALL
    rocksdb.cpp
  )

  enableLinkWholeArchive(osquery_database_plugins_rocksdb)

  target_link_libraries(osquery_database_plugins_rocksdb PUBLIC
    global_cxx_settings
    osquery_core
    osquery_database
    osquery_registry
    osquery_utils
    thirdparty_googletest
    thirdparty_rocksdb
  )

  set(public_header_files
    rocksdb.h
  )

  generateIncludeNamespace(osquery_database_plugins_rocksdb "osquery/database/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryDatabasePluginsSqlite)
  add_library(osquery_database_plugins_sqlite EXCLUDE_FROM_ALL
    sqlite.cpp
  )

  enableLinkWholeArchive(osquery_database_plugins_sqlite)

  target_link_libraries(osquery_database_plugins_sqlite PUBLIC
    global_cxx_settings
    osquery_core
    osquery_database
    osquery_filesystem
    osquery_registry
    osquery_utils
    thirdparty_sqlite
  )

  set(public_header_files
    sqlite.h
  )

  generateIncludeNamespace(osquery_database_plugins_sqlite "osquery/database/plugins" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_database_plugins_main()

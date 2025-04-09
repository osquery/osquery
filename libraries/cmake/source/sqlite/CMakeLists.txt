# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(sqliteMain)

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(parameter_list
    "SQLITE_MAX_VARIABLE_NUMBER=250000"
  )

  set(option_list
    SQLITE_ENABLE_COLUMN_METADATA
    SQLITE_SECURE_DELETE
    SQLITE_ENABLE_DBSTAT_VTAB
    SQLITE_SOUNDEX
    SQLITE_ENABLE_EXPLAIN_COMMENTS
  )

  add_library(thirdparty_sqlite
    "${library_root}/src/sqlite3.c"
  )

  target_compile_definitions(thirdparty_sqlite PRIVATE
    ${parameter_list}
  )

  foreach(option ${option_list})
    target_compile_definitions(thirdparty_sqlite PRIVATE
      "${option}=1"
    )
  endforeach()

  target_include_directories(thirdparty_sqlite INTERFACE
    "${library_root}/src"
  )

  target_link_libraries(thirdparty_sqlite PRIVATE
    thirdparty_c_settings
  )

  if(DEFINED PLATFORM_POSIX)
    # Allow tables to rethrow exceptions
    target_compile_options(thirdparty_sqlite PRIVATE
      -fexceptions
    )
  endif()
endfunction()

sqliteMain()

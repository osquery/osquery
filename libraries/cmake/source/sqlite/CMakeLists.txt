# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(sqliteMain)
  set(SQLITE_GENERATE_INSTALL_TARGET false CACHE BOOL "" FORCE)
  add_subdirectory(src)

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

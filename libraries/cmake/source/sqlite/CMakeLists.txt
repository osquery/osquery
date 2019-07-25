# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(sqliteMain)
  add_subdirectory(src)
  target_link_libraries(thirdparty_sqlite PUBLIC
    global_c_settings
  )

  target_link_libraries(thirdparty_sqlite PRIVATE
    thirdparty_source_module_warnings
  )
endfunction()

sqliteMain()

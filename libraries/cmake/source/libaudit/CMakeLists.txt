# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libauditMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libaudit
    "${library_root}/lib/audit_logging.c"
    "${library_root}/lib/deprecated.c"
    "${library_root}/lib/libaudit.c"
    "${library_root}/lib/lookup_table.c"
    "${library_root}/lib/message.c"
    "${library_root}/lib/netlink.c"
    "${library_root}/lib/strsplit.c"
  )

  target_compile_definitions(thirdparty_libaudit PRIVATE
    _GNU_SOURCE
    HAVE_CONFIG_H
    PIC
  )

  target_link_libraries(thirdparty_libaudit PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libaudit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${library_root}"
    "${library_root}/auparse"
    "${library_root}/lib"
  )

  target_include_directories(thirdparty_libaudit SYSTEM INTERFACE
    "${library_root}/lib"
  )
endfunction()

libauditMain()

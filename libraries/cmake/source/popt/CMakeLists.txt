# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(poptMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_popt
    "${library_root}/popt.c"
    "${library_root}/poptparse.c"
    "${library_root}/poptconfig.c"
    "${library_root}/popthelp.c"
    "${library_root}/poptint.c"
    "${library_root}/test1.c"
    "${library_root}/test2.c"
    "${library_root}/tdict.c"
    "${library_root}/poptconfig.c"
    "${library_root}/popt.c"
    "${library_root}/poptint.c"
    "${library_root}/poptparse.c"
    "${library_root}/popthelp.c"
  )

  target_link_libraries(thirdparty_popt PUBLIC
    global_c_settings
  )

  target_link_libraries(thirdparty_popt PRIVATE
    thirdparty_source_module_warnings
  )

  target_compile_definitions(thirdparty_popt PRIVATE
    _GNU_SOURCE
    HAVE_CONFIG_H
    _REENTRANT  
  )

  target_include_directories(thirdparty_popt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
    "${library_root}"
  )

  target_include_directories(thirdparty_popt SYSTEM INTERFACE
    "${library_root}"
  )
endfunction()

poptMain()

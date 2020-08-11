# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(poptMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_popt
    "${library_root}/popt.c"
    "${library_root}/poptparse.c"
    "${library_root}/poptconfig.c"
    "${library_root}/popthelp.c"
    "${library_root}/poptint.c"
  )

  target_link_libraries(thirdparty_popt PRIVATE
    thirdparty_c_settings
  )

  target_compile_definitions(thirdparty_popt PRIVATE
    _GNU_SOURCE
    HAVE_CONFIG_H
    _REENTRANT  
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_popt PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_popt PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos"
    )
  endif()

  target_include_directories(thirdparty_popt PRIVATE
    "${library_root}"
  )

  target_include_directories(thirdparty_popt SYSTEM INTERFACE
    "${library_root}"
  )
endfunction()

poptMain()

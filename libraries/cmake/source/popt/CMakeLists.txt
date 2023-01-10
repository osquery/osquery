# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(poptMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_popt
    "${library_root}/src/popt.c"
    "${library_root}/src/poptparse.c"
    "${library_root}/src/poptconfig.c"
    "${library_root}/src/popthelp.c"
    "${library_root}/src/poptint.c"
  )

  target_link_libraries(thirdparty_popt PRIVATE
    thirdparty_c_settings
  )

  target_compile_definitions(thirdparty_popt PRIVATE
    HAVE_CONFIG_H
    POPT_SYSCONFDIR=\"/usr/local/etc\"
  )

  target_include_directories(thirdparty_popt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}"
    "${library_root}/src"
  )

  target_include_directories(thirdparty_popt SYSTEM INTERFACE
    "${library_root}/src"
  )
endfunction()

poptMain()

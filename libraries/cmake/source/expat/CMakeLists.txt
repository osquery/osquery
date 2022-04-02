# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(expatMain)
  add_library(thirdparty_expat
    "${CMAKE_CURRENT_SOURCE_DIR}/src/expat/lib/xmlparse.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/expat/lib/xmlrole.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/expat/lib/xmltok.c"
  )

  target_compile_options(thirdparty_expat PRIVATE
    -fno-strict-aliasing
  )

  target_include_directories(thirdparty_expat PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/linux"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/expat/lib"
  )

  target_link_libraries(thirdparty_expat PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_expat SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/expat/lib"
  )

  target_compile_definitions(thirdparty_expat PRIVATE
    HAVE_EXPAT_CONFIG_H
  )
endfunction()

expatMain()

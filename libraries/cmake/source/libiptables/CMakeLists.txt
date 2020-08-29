# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libiptablesMain)
  # We only really want the libiptc component
  generateLibiptc()

  add_library(thirdparty_libiptables INTERFACE)
  target_link_libraries(thirdparty_libiptables INTERFACE thirdparty_libiptc)
endfunction()

function(generateLibiptc)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_libiptc
    "${library_root}/libiptc/libip4tc.c"
    "${library_root}/libiptc/libip6tc.c"
  )

  target_compile_definitions(thirdparty_libiptc PRIVATE
    HAVE_CONFIG_H
    _LARGEFILE_SOURCE=1
    _LARGE_FILES
    _FILE_OFFSET_BITS=64
    _REENTRANT
    XTABLES_LIBDIR=\"/usr/local/lib/xtables\"
    XTABLES_INTERNAL
  )

  target_link_libraries(thirdparty_libiptc PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_libiptc PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"

    "${library_root}"
    "${library_root}/libiptc"
    "${library_root}/include"
  )

  set(public_header_list
    "libiptc/libip6tc.h"
    "libiptc/xtcshared.h"
    "libiptc/ipt_kernel_headers.h"
    "libiptc/libxtc.h"
    "libiptc/libiptc.h"
    "xtables.h"
  )

  foreach(public_header ${public_header_list})
    configure_file(
      "${library_root}/include/${public_header}"
      "${CMAKE_CURRENT_BINARY_DIR}/include/${public_header}"
      COPYONLY
    )
  endforeach()

  target_include_directories(thirdparty_libiptc SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/include"
  )
endfunction()

libiptablesMain()


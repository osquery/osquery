# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(compoundfilereader)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  add_library(thirdparty_compoundfilereader INTERFACE)
  target_include_directories(thirdparty_compoundfilereader INTERFACE
    "${library_root}/src/include"
  )
endfunction()

compoundfilereader()
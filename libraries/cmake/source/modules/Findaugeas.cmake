# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

importSourceSubmodule(
  NAME "augeas/gnulib"

  SHALLOW_SUBMODULES "src"
)

importSourceSubmodule(
  NAME "augeas"

  NO_RECURSIVE

  SHALLOW_SUBMODULES "src"

  PATCH "src"
)

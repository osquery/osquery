# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

importSourceSubmodule(
  NAME "aws-sdk-cpp"

  SHALLOW_SUBMODULES
    "aws-c-common_src"
    "aws-c-event-stream_src"
    "aws-checksums_src"
    "aws-sdk-cpp_src"
)

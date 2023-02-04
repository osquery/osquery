# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

cmake_minimum_required(VERSION 3.14.6)
include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

importSourceSubmodule(
  NAME "grpc"

  NO_RECURSIVE

  SUBMODULES
    "src"
    "src/third_party/abseil-cpp"

  SHALLOW_SUBMODULES
    "src/third_party/cares/cares"
    "src/third_party/protobuf"
    "src/third_party/re2"

  PATCH
    "src"
)

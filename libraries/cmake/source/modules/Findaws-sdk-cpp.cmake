
# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

importSourceSubmodule(
  NAME
    "aws-sdk-cpp"

  NO_RECURSIVE

  SHALLOW_SUBMODULES
    "src/aws-c-auth"
    "src/aws-c-cal"
    "src/aws-c-common"
    "src/aws-c-compression"
    "src/aws-c-event-stream"
    "src/aws-checksums"
    "src/aws-c-http"
    "src/aws-c-io"
    "src/aws-c-mqtt"
    "src/aws-crt-cpp"
    "src/aws-c-s3"
    "src/aws-sdk-cpp"
    "src/s2n"
)
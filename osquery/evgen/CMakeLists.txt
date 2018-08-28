# Copyright (c) 2018-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed as defined on the LICENSE file found in the
# root directory of this source tree.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/linux/udev.cpp"
)

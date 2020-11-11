# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

project("config_plugin_extension")

addOsqueryExtension(
  "${PROJECT_NAME}"
  main.cpp
)

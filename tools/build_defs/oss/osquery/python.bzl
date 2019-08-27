# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

load("//tools/build_defs/oss/osquery:native_functions.bzl", "osquery_native")

def osquery_python_library(**kwargs):
    osquery_native.python_library(**kwargs)

def osquery_python_binary(**kwargs):
    osquery_native.python_binary(**kwargs)

def osquery_prebuilt_python_library(**kwargs):
    osquery_native.prebuilt_python_library(**kwargs)

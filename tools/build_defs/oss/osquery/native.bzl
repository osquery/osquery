# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

load(
    "//tools/build_defs/oss/osquery:defaults.bzl",
    _OSQUERY_ROOT_TARGET_PATH = "OSQUERY_ROOT_TARGET_PATH",
)
load("//tools/build_defs/oss/osquery:native_functions.bzl", "osquery_native")

def osquery_get_os():
    if native.host_info().os.is_linux:
        return "linux"
    elif native.host_info().os.is_macos:
        return "macos"
    elif native.host_info().os.is_freebsd:
        return "freebsd"
    elif native.host_info().os.is_windows:
        return "windows"
    return "unknown"

def osquery_get_arch():
    if native.host_info().arch.is_x86_64:
        return "x86_64"
    return "unknown"

def osquery_get_current_platform():
    return "{}-{}".format(osquery_get_os(), osquery_get_arch())

def osquery_target(target):
    return "{}{}".format(_OSQUERY_ROOT_TARGET_PATH, target)

def osquery_genrule(**kwargs):
    osquery_native.genrule(**kwargs)

def osquery_filegroup(**kwargs):
    osquery_native.filegroup(**kwargs)

def osquery_http_archive(**kwargs):
    osquery_native.http_archive(**kwargs)

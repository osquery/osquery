# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

LINUX = "linux-x86_64"

MACOSX = "macosx-x86_64"

WINDOWS = "windows-x86_64"

FREEBSD = "freebsd-x86_64"

POSIX = "({})|({})|({})".format(MACOSX, LINUX, FREEBSD)

#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

# This script is called by the cpack macOS packaging tools. It is
# meant to be a drop in replacement for `pkgbuild`, but overrides the
# package identifier option.
#
# It is configured by the cpack variables CPACK_COMMAND_PKGBUILD more info in the source code.
# https://github.com/Kitware/CMake/blob/master/Source/CPack/cmCPackProductBuildGenerator.cxx

set -e

args=()

# loop over the args, and populate the args array. remove identifier
# arguments. This assumes a `--identifier foo` style, and will break
# if `--identifier=foo` is used.
while [ "$1" != "" ]; do
    if [ "$1" == "--identifier" ]; then
        shift
        shift
    fi

    args+=("$1")
    shift
done

# set identifier as we desire
if [ ! -z "$PKG_IDENTIFIER" ]; then
    args+=(--identifier "$PKG_IDENTIFIER")
fi

# hand off to pkgbuild
exec pkgbuild "${args[@]}"

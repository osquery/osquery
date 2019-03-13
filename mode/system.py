#!/usr/bin/env python2
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

import sys
import argparse
import platform
import itertools


PLATFORM_CXX_FLAGS = {
    "linux": {
        "release": [
            "//tools/buckconfigs/linux-x86_64/toolchain/ubuntu-18.04-clang.bcfg",
            "//tools/buckconfigs/linux-x86_64/type/release.bcfg",
            "//tools/buckconfigs/linux-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
        "debug": [
            "//tools/buckconfigs/linux-x86_64/toolchain/ubuntu-18.04-clang.bcfg",
            "//tools/buckconfigs/linux-x86_64/type/debug.bcfg",
            "//tools/buckconfigs/linux-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
    },
    "freebsd": {
        "release": [
            "//tools/buckconfigs/freebsd-x86_64/toolchain/freebsd-11.2-clang.bcfg",
            "//tools/buckconfigs/freebsd-x86_64/type/release.bcfg",
            "//tools/buckconfigs/freebsd-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
        "debug": [
            "//tools/buckconfigs/freebsd-x86_64/toolchain/freebsd-11.2-clang.bcfg",
            "//tools/buckconfigs/freebsd-x86_64/type/debug.bcfg",
            "//tools/buckconfigs/freebsd-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
    },
    "darwin": {
        "release": [
            "//tools/buckconfigs/macos-x86_64/type/release.bcfg",
            "//tools/buckconfigs/macos-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
        "debug": [
            "//tools/buckconfigs/macos-x86_64/type/debug.bcfg",
            "//tools/buckconfigs/macos-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
    },
    "windows": {
        "release": [
            "//tools/buckconfigs/windows-x86_64/toolchain/vsToolchainFlags.bcfg",
            "//tools/buckconfigs/windows-x86_64/type/release.bcfg",
            "//tools/buckconfigs/windows-x86_64/python/default.bcfg",
            "//tools/buckconfigs/windows-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
        "debug": [
            "//tools/buckconfigs/windows-x86_64/toolchain/vsToolchainFlags.bcfg",
            "//tools/buckconfigs/windows-x86_64/type/debug.bcfg",
            "//tools/buckconfigs/windows-x86_64/python/default.bcfg",
            "//tools/buckconfigs/windows-x86_64/base.bcfg",
            "//tools/buckconfigs/base.bcfg",
        ],
    },
}

SUPPORTED_FLAVORS = ["debug", "release"]


def generate(flavor):
    osType, _, _, _, _, _ = platform.uname()
    osType = osType.lower()
    if osType not in PLATFORM_CXX_FLAGS:
        raise Exception("Platform {} not supported!".format(osType))
    return PLATFORM_CXX_FLAGS[osType][flavor]


# Buck does not allow this script to fail, so lets pass an invalid flag ---- to
# make buck fail and print a message inside --- || || ----. This is bad but at
# least we're printing something to the user.
def fail(message):
    print("---- || {} || ----".format(message))
    sys.exit(1)


if __name__ == "__main__":

    class ThrowingArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            fail(message)

    parser = ThrowingArgumentParser(
        description="Automatically set the proper config files for buck. This is selected based on the platform"
    )
    parser.add_argument(
        "--flavors",
        dest="flavors",
        action="store",
        type=str,
        help="comma seperated list of flavors. Currently supported: release and debug",
        choices=SUPPORTED_FLAVORS,
        default="release",
    )

    args = parser.parse_args()
    configs = ["--config-file\n{}".format(config) for config in generate(args.flavors)]
    print("\n".join(configs))

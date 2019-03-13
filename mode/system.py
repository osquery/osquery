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

SUPPORTED_FLAVORS = {e for entry in PLATFORM_CXX_FLAGS.values() for e in entry}


def generate(flavors):
    osType, _, _, _, _, _ = platform.uname()
    osType = osType.lower()
    if osType not in PLATFORM_CXX_FLAGS:
        raise Exception("Platform {} not supported!".format(osType))
    return itertools.chain.from_iterable(
        [PLATFORM_CXX_FLAGS[osType][flavor] for flavor in flavors]
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automatically set the proper config files for buck. This is selected based on the platform"
    )
    parser.add_argument(
        "--flavors",
        dest="flavors",
        action="store",
        type=str,
        help="comma seperated list of flavors. Currently supported: release and debug",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    flavors = {flavor.lower() for flavor in args.flavors.split(",")}
    if len(flavors - SUPPORTED_FLAVORS) > 0:
        print(
            "Invalid flavors were given: {}\n".format(
                ",".join(flavors - SUPPORTED_FLAVORS)
            )
        )
        parser.print_help(sys.stderr)
    else:
        configs = ["--config-file\n{}".format(config) for config in generate(flavors)]
        print("\n".join(configs))

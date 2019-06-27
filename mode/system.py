#!/usr/bin/env python2
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

import sys
import argparse
import platform


class Platform:
    LINUX_X86_64 = "linux-x86_64"
    MACOS_X86_64 = "macos-x86_64"
    FREEBSD_X86_64 = "freebsd-x86_64"
    WINDOWS_X86_64 = "windows-x86_64"


class BuildType:
    RELEASE = "release"
    DEBUG = "debug"


BCFG_BASE_PATH = "//tools"


PLATFORM_TOOLCHAIN = {
    Platform.LINUX_X86_64: "ubuntu-18.04-clang",
    Platform.MACOS_X86_64: None,
    Platform.FREEBSD_X86_64: "freebsd-11.2-clang",
    Platform.WINDOWS_X86_64: "vsToolchainFlags",
}


def generate_config_file_flag(bcfg):
    return "--config-file\n" + bcfg if bcfg else ""


def generate_toolchain(build_platform, build_type):
    toolchain = PLATFORM_TOOLCHAIN[build_platform]

    if toolchain is not None:
        bcfg = "{}/buckconfigs/{}/toolchain/{}.bcfg".format(
            BCFG_BASE_PATH, build_platform, toolchain
        )
    else:
        bcfg = None

    return generate_config_file_flag(bcfg)


def generate_type(build_platform, build_type):
    bcfg = "{}/buckconfigs/{}/type/{}.bcfg".format(
        BCFG_BASE_PATH, build_platform, build_type
    )

    return generate_config_file_flag(bcfg)


def generate_platform_base(build_platform):
    bcfg = "{}/buckconfigs/{}/base.bcfg".format(BCFG_BASE_PATH, build_platform)

    return generate_config_file_flag(bcfg)


def generate_base():
    bcfg = "{}/buckconfigs/base.bcfg".format(BCFG_BASE_PATH)

    return generate_config_file_flag(bcfg)


# Buck does not allow this script to fail, so lets pass an invalid flag ---- to
# make buck fail and print a message inside --- || || ----. This is bad but at
# least we're printing something to the user.
def fail(message):
    print("---- || {} || ----".format(message))
    sys.exit(1)


def get_platform():
    os = platform.system().lower()
    arch = platform.machine().lower()

    if os == "linux" and arch == "x86_64":
        return Platform.LINUX_X86_64
    elif os == "darwin" and arch == "x86_64":
        return Platform.MACOS_X86_64
    elif os == "freebsd" and arch == "x86_64":
        return Platform.FREEBSD_X86_64
    elif os == "windows" and arch == "x86_64":
        return Platform.WINDOWS_X86_64
    else:
        fail("Unsupported platform {} {}".format(os, arch))


def get_build_type(build_type):
    if build_type == "release":
        return BuildType.RELEASE
    elif build_type == "debug":
        return BuildType.DEBUG
    else:
        fail("Unsupported build type {}".format(build_type))


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
        choices=[BuildType.RELEASE, BuildType.DEBUG],
        default=BuildType.RELEASE,
    )

    args = parser.parse_args()

    build_platform = get_platform()
    build_type = get_build_type(args.flavors)

    configs = [
        generate_toolchain(build_platform, build_type),
        generate_type(build_platform, build_type),
        generate_platform_base(build_platform),
        generate_base(),
    ]
    print("\n".join(configs))

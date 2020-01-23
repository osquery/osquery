# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

load(
    "//tools/build_defs/oss/osquery:native_functions.bzl",
    _osquery_custom_set_generic_kwargs = "osquery_custom_set_generic_kwargs",
    _osquery_cxx_binary = "osquery_cxx_binary",
    _osquery_cxx_library = "osquery_cxx_library",
    _osquery_cxx_test = "osquery_cxx_test",
    _osquery_native = "osquery_native",
    _osquery_prebuilt_cxx_library = "osquery_prebuilt_cxx_library",
    _osquery_prebuilt_cxx_library_group = "osquery_prebuilt_cxx_library_group",
    _osquery_read_config = "osquery_read_config",
)
load(
    "//tools/build_defs/oss/osquery:platforms.bzl",
    _FREEBSD = "FREEBSD",
    _LINUX = "LINUX",
    _MACOSX = "MACOSX",
    _WINDOWS = "WINDOWS",
)
load(
    ":defaults.bzl",
    _LABELS = "OSQUERY_LABELS",
)

# for osquery targets only
_OSQUERY_PLATFORM_PREPROCESSOR_FLAGS = [
    (
        _LINUX,
        [
            "-DLINUX=1",
            "-DPOSIX=1",
            "-DOSQUERY_LINUX=1",
            "-DOSQUERY_POSIX=1",
            "-DOSQUERY_BUILD_PLATFORM=linux",
            "-DOSQUERY_BUILD_DISTRO=centos7",
        ],
    ),
    (
        _MACOSX,
        [
            "-DAPPLE=1",
            "-DDARWIN=1",
            "-DBSD=1",
            "-DPOSIX=1",
            "-DOSQUERY_POSIX=1",
            "-DOSQUERY_BUILD_PLATFORM=darwin",
            "-DOSQUERY_BUILD_DISTRO=10.12",
        ],
    ),
    (
        _FREEBSD,
        [
            "-DFREEBSD=1",
            "-DBSD=1",
            "-DPOSIX=1",
            "-DOSQUERY_POSIX=1",
            "-DOSQUERY_FREEBSD=1",
            "-DOSQUERY_BUILD_PLATFORM=freebsd",
            "-DOSQUERY_BUILD_DISTRO=11.2",
        ],
    ),
    (
        _WINDOWS,
        [
            "-DWIN32=1",
            "-DWINDOWS=1",
            "-DOSQUERY_WINDOWS=1",
            "-DOSQUERY_BUILD_PLATFORM=windows",
            "-DOSQUERY_BUILD_DISTRO=10",
        ],
    ),
]

# for all targets in osquery build, including third party
_GLOBAL_PLATFORM_PREPROCESSOR_FLAGS = [
    (
        _WINDOWS,
        [
            "/D_WIN32_WINNT=_WIN32_WINNT_WIN7",
            "/DNTDDI_VERSION=NTDDI_WIN7",
        ],
    ),
]

def _osquery_set_generic_kwargs(kwargs):
    _osquery_custom_set_generic_kwargs(kwargs)
    kwargs.setdefault("labels", [])
    kwargs["labels"] += _LABELS

def _osquery_set_preprocessor_kwargs(kwargs, external):
    kwargs.setdefault("preprocessor_flags", [])
    kwargs.setdefault("platform_preprocessor_flags", [])
    kwargs["platform_preprocessor_flags"] += _GLOBAL_PLATFORM_PREPROCESSOR_FLAGS
    if not external:
        kwargs["platform_preprocessor_flags"] += _OSQUERY_PLATFORM_PREPROCESSOR_FLAGS

def _is_target_ignored(target):
    if _osquery_read_config("osquery", "disable_ignore_lists", False):
        return False
    ignore_list = _osquery_read_config("osquery", "target_ignore_list", [])
    return target in ignore_list

def osquery_cxx_library(external = False, **kwargs):
    if _is_target_ignored(kwargs["name"]):
        _osquery_cxx_library(name = kwargs["name"], visibility = kwargs.get("visibility", []))
    else:
        _osquery_set_generic_kwargs(kwargs)
        _osquery_set_preprocessor_kwargs(kwargs, external)

        #TODO remove after T39415423 is done
        # platform_deps is ignored in xcode project generation
        # so we need to move osx platform_deps to regular deps
        if _osquery_read_config("osquery", "xcode", False):
            platform_deps = kwargs.get("platform_deps", [])
            deps = kwargs.get("deps", [])
            for (platform, new_deps) in platform_deps:
                if "macos" in platform:
                    deps += new_deps
            kwargs["deps"] = deps
        _osquery_cxx_library(**kwargs)

def osquery_prebuilt_cxx_library(**kwargs):
    _osquery_set_generic_kwargs(kwargs)
    _osquery_prebuilt_cxx_library(**kwargs)

def osquery_prebuilt_cxx_library_group(**kwargs):
    kwargs.setdefault("labels", [])
    kwargs["labels"] += _LABELS
    _osquery_prebuilt_cxx_library_group(**kwargs)

def osquery_cxx_binary(external = False, **kwargs):
    _ignore = [external]
    _osquery_set_generic_kwargs(kwargs)
    _osquery_set_preprocessor_kwargs(kwargs, external)
    if host_info().os.is_macos:
        not_supported_key = "platforms"
        if not_supported_key in kwargs:
            kwargs.pop(not_supported_key)
        _osquery_native.apple_binary(**kwargs)
    else:
        _osquery_cxx_binary(**kwargs)

def osquery_cxx_test(external = False, **kwargs):
    _ignore = [external]
    _osquery_set_generic_kwargs(kwargs)
    _osquery_set_preprocessor_kwargs(kwargs, external)

    kwargs.setdefault("platform_preprocessor_flags", [])
    kwargs["platform_preprocessor_flags"].append(
        (
            _MACOSX,
            [
                # osquery tests have lots of ASSERT_/EXPECT_ to compare signed
                # const with unsigned value. It requires some effort to fix it
                # with small value, because it is just tests.
                "-Wno-sign-compare",
            ],
        ),
    )

    _osquery_cxx_test(**kwargs)

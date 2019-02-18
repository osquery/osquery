"""Implementation of osquery code generation targets"""
"""Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved"""

load(
    "//tools/build_defs/oss/osquery:cxx.bzl",
    "osquery_cxx_library",
)
load(
    "//tools/build_defs/oss/osquery:native.bzl",
    "osquery_genrule",
    "osquery_target",
)
load(
    "//tools/build_defs/oss/osquery:native_functions.bzl",
    _osquery_read_config = "osquery_read_config",
)

def _impl_gen_cxx_from_spec(name, spec_file, is_foreign = False):
    table_root_name = spec_file.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    table_target_name = "{}_{}.table".format(name, table_root_name)
    row_genrule_name = "{}_{}.row_genrule".format(name, table_root_name)
    row_target_name = "{}_{}_row".format(name, table_root_name)
    row_header_name = "{}.h".format(table_root_name)

    cmd = "$(exe {})".format(osquery_target("tools/codegen:gentable"))
    foreign = "--foreign" if is_foreign else ""
    templates = "$(location {})/templates".format(osquery_target("tools/codegen:templates"))
    spec_file = spec_file
    output = "$OUT"

    osquery_genrule(
        name = table_target_name,
        out = "{}.cpp".format(table_root_name),
        cmd = (
            "{cmd} {foreign} --templates {templates} {spec_file} {output}"
        ).format(
            cmd = cmd,
            foreign = foreign,
            templates = templates,
            spec_file = spec_file,
            output = output,
        ),
    )

    osquery_genrule(
        name = row_genrule_name,
        out = "{}.h".format(table_root_name),
        cmd = (
            "{cmd} --header --templates {templates} {spec_file} {output}"
        ).format(
            cmd = cmd,
            templates = templates,
            spec_file = spec_file,
            output = output,
        ),
    )

    osquery_cxx_library(
        name = row_target_name,
        exported_headers = {
            row_header_name: ":" + row_genrule_name,
        },
        header_namespace = "osquery/rows",
        visibility = [
            osquery_target("osquery/tables/..."),
        ],
    )

    return [table_target_name, row_genrule_name]

def _impl_gen_amalgamation(name, cxx_targets, is_foreign = False):
    category = "foreign" if is_foreign else "native"
    target_name = "{}_{}_amalgamation".format(name, category)
    out_cpp = "{}_amalgamation.cpp".format(category)

    osquery_genrule(
        name = target_name,
        srcs = [
            ":{}".format(cxx_target)
            for cxx_target in cxx_targets
        ],
        out = out_cpp,
        cmd = (
            "{cmd} {foreign} --templates {templates} --category {category} --sources {sources} --output {output}"
        ).format(
            cmd = "$(exe {})".format(osquery_target("tools/codegen:amalgamate")),
            foreign = "--foreign" if is_foreign else "",
            templates = "$(location {})/templates".format(osquery_target("tools/codegen:templates")),
            category = category,
            sources = "$SRCDIR",
            output = "$OUT",
        ),
    )

    return target_name

def _impl_gen_library(name, targets, deps, **kwargs):
    if deps == None:
        deps = []

    headers = osquery_target("osquery:headers")
    if headers not in deps:
        deps += [
            headers,
        ]

    osquery_cxx_library(
        name = name,
        srcs = [
            ":{}".format(target)
            for target in targets
        ],
        deps = deps,
        **kwargs
    )

def _is_spec_ignored(spec):
    if _osquery_read_config("osquery", "disable_ignore_lists", False):
        return False
    ignore_list = _osquery_read_config("osquery", "spec_ignore_list", [])
    return spec in ignore_list

def _impl_is_foreign(platform_def):
    return not (
        host_info().os.is_linux and "linux" in platform_def or
        host_info().os.is_macos and "macos" in platform_def or
        host_info().os.is_windows and "windows" in platform_def or
        host_info().os.is_freebsd and "freebsd" in platform_def or
        host_info().os.is_unknown
    )

def osquery_gentable_cxx_library(name, spec_location, spec_files = None, platform_spec_files = None, deps = None, **kwargs):
    """
    Code generation target for osquery tables

    Args:
        name (str): The target name.
        spec_files (list or None): List spec files for tables available on all platforms.
        platform_spec_files (list or None): List spec files for platform specific tables and associated platforms, specified as a tuple where the first item is the spec file and the second a coma separated list of platforms (e.g. "linux,windows" or "macos,freebsd,linux").
        deps (list): List of dependencies.
    """
    native_cxx_targets = []
    if not spec_location.endswith("/"):
        spec_location += "/"
    native_specs = []
    foreign_specs = []

    if spec_files:
        for spec_file in spec_files:
            if _is_spec_ignored(spec_file):
                foreign_specs.append(spec_file)
            else:
                native_specs.append(spec_file)

    foreign_cxx_targets = []
    if platform_spec_files:
        for spec_file, platform_def in platform_spec_files:
            if _impl_is_foreign(platform_def) or _is_spec_ignored(spec_file):
                foreign_specs.append(spec_file)
            else:
                native_specs.append(spec_file)

    for spec_file in native_specs:
        native_cxx_targets.extend(
            _impl_gen_cxx_from_spec(
                name,
                spec_location + spec_file,
                is_foreign = False,
            ),
        )

    for spec_file in foreign_specs:
        foreign_cxx_targets.extend(
            _impl_gen_cxx_from_spec(
                name,
                spec_location + spec_file,
                is_foreign = True,
            ),
        )

    native_amalgamation_target = _impl_gen_amalgamation(
        name,
        native_cxx_targets,
    )

    foreign_amalgamation_target = _impl_gen_amalgamation(
        name,
        foreign_cxx_targets,
        is_foreign = True,
    )

    _impl_gen_library(
        name,
        [
            native_amalgamation_target,
            foreign_amalgamation_target,
        ],
        deps,
        **kwargs
    )

"""Implementation of osquery code generation targets"""

load(
    "//tools/build_defs/oss/osquery:cxx.bzl",
    "osquery_cxx_library",
)
load(
    "//tools/build_defs/oss/osquery:native.bzl",
    "osquery_genrule",
    "osquery_target",
)

def _impl_gen_cxx_from_spec(name, spec_file, is_foreign = False):
    target_name = "{}_{}".format(
        name,
        spec_file.rsplit("/", 1)[-1],
    )

    osquery_genrule(
        name = target_name,
        out = "{}.cpp".format(target_name),
        cmd = (
            "{cmd} {foreign} --templates {templates} {spec_file} {output}"
        ).format(
            cmd = "$(exe {})".format(osquery_target("tools/codegen:gentable")),
            foreign = "--foreign" if is_foreign else "",
            templates = "$(location {})/templates".format(osquery_target("tools/codegen:templates")),
            spec_file = spec_file,
            output = "$OUT",
        ),
    )

    return target_name

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

def _impl_is_foreign(platform_def):
    return not (
        host_info().os.is_linux and "linux" in platform_def or
        host_info().os.is_macos and "macos" in platform_def or
        host_info().os.is_windows and "windows" in platform_def or
        host_info().os.is_freebsd and "freebsd" in platform_def or
        host_info().os.is_unknown
    )

def osquery_gentable_cxx_library(name, spec_files = None, platform_spec_files = None, deps = None, **kwargs):
    """
    Code generation target for osquery tables

    Args:
        name (str): The target name.
        spec_files (list or None): List spec files for tables available on all platforms.
        platform_spec_files (list or None): List spec files for platform specific tables and associated platforms, specified as a tuple where the first item is the spec file and the second a coma separated list of platforms (e.g. "linux,windows" or "macos,freebsd,linux").
        deps (list): List of dependencies.
    """
    native_cxx_targets = []
    if spec_files:
        for spec_file in spec_files:
            native_cxx_targets.append(
                _impl_gen_cxx_from_spec(
                    name,
                    spec_file,
                    is_foreign = False,
                ),
            )

    foreign_cxx_targets = []
    if platform_spec_files:
        for spec_file, platform_def in platform_spec_files:
            if _impl_is_foreign(platform_def):
                foreign_cxx_targets.append(
                    _impl_gen_cxx_from_spec(
                        name,
                        spec_file,
                        is_foreign = True,
                    ),
                )
            else:
                native_cxx_targets.append(
                    _impl_gen_cxx_from_spec(
                        name,
                        spec_file,
                        is_foreign = False,
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

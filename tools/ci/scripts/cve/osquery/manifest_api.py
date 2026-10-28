#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import sys

# These libraries are not Github submodules, so there's no commit to check
libraries_without_commit = ["openssl"]

# There are no CPE for these libraries
libraries_without_cpe = [
    "ebpfpub",
    "linuxevents",
    "gflags",
    "glog",
    "librdkafka",
    "linenoise-ng",
    "aws-c-auth",
    "aws-c-cal",
    "aws-c-auth",
    "aws-c-cal",
    "aws-c-common",
    "aws-c-compression",
    "aws-c-event-stream",
    "aws-c-http",
    "aws-c-io",
    "aws-c-mqtt",
    "aws-c-s3",
    "aws-checksums",
    "aws-crt-cpp",
    "aws-sdk-cpp",
    "s2n",
]

# These libraries will be ignored from the up to date version check
libraries_to_ignore = ["googletest"]

# These libraries have no version; the date will be checked instead
libraries_without_version = ["gnulib"]


def print_err(message: str):
    print("Error: " + message, file=sys.stderr)


def validateManifestFormat(manifest: dict) -> bool:

    fields_no_commit = [("product", str), ("vendor", str), ("version", str), ("ignored-cves", list)]
    fields_no_version = [("product", str), ("vendor", str), ("date", str), ("ignored-cves", list)]
    fields_no_cpe = [("vendor", str), ("commit", str)]
    all_fields = fields_no_commit + [("commit", str)]

    for library_name, library_metadata in manifest.items():

        if library_name in libraries_without_cpe:
            fields_to_check = fields_no_cpe
        elif library_name in libraries_without_commit:
            fields_to_check = fields_no_commit
        elif library_name in libraries_without_version:
            fields_to_check = fields_no_version
        else:
            fields_to_check = all_fields

        if library_name.strip() == "":
            print_err("Manifest contains a library without name")
            return False

        for field_name, field_type in fields_to_check:
            if field_name not in library_metadata:
                print_err(f"Library {library_name}, missing {field_name} field")
                return False

            if not isinstance(library_metadata[field_name], field_type):
                print_err(
                    f"Library {library_name}, the {field_name} field is not of type {field_type}"
                )
                return False

            if field_type == str:
                if library_metadata[field_name].strip() == "":
                    print_err(f"Library {library_name}, the {field_name} field is empty")
                    return False

    return True


def validateLibrariesVersions(
    manifest: dict, versions: "list[tuple]", commits: "list[tuple]"
) -> bool:

    manifest_is_valid = True

    # Remove ignored libraries
    versions = [v for v in versions if not v[0] in libraries_to_ignore]

    # First we search for libraries that are present
    for library_name, current_library_version in versions:

        if library_name not in manifest:
            manifest_is_valid = False
            print_err(
                f"Library {library_name} is missing from the manifest, please refer to"
                " https://osquery.readthedocs.io/en/latest/development/cve-scan/#adding-a-new-library"
                " and special cases on how to add it"
            )
            continue

        manifest_library_version = manifest[library_name]["version"]

        if current_library_version != manifest_library_version:
            manifest_is_valid = False
            print_err(
                f"Library {library_name} has an outdated version in the manifest. Expected"
                f" {current_library_version}, found {manifest_library_version}. Update the manifest"
            )

    # Remove ignored libraries
    commits = [c for c in commits if not c[0] in libraries_to_ignore]

    for library_name, current_library_commit in commits:

        if library_name not in manifest:
            manifest_is_valid = False
            print_err(
                f"Library {library_name} is missing from the manifest, please refer to"
                " https://osquery.readthedocs.io/en/latest/development/cve-scan/#adding-a-new-library"
                " and special cases on how to add it"
            )
            continue

        manifest_library_commit = manifest[library_name]["commit"]

        if current_library_commit != manifest_library_commit:
            manifest_is_valid = False
            print_err(
                f"Library {library_name} has an outdated commit in the manifest. Expected"
                f" {current_library_commit}, found {manifest_library_commit}. Please update both"
                " the commit and the version when applicable"
            )

    manifest_libraries_names = set(list(zip(*manifest.items()))[0])

    submodule_names = set(list(zip(*commits))[0])
    externallibs_names = set(list(zip(*versions))[0])

    all_detected_libs = set.union(submodule_names, externallibs_names)

    diff = list(manifest_libraries_names - all_detected_libs)

    if len(diff) > 0:
        print("Additional libraries found in the manifest that can be removed:")
        for library_name in diff:
            print(library_name)

    return manifest_is_valid

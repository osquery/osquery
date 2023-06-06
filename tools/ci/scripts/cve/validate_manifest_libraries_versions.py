#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

from importlib.resources import path
from osquery.manifest_api import validateLibrariesVersions, validateManifestFormat
import argparse
import pygit2
import pathlib
import re
import json

parser = argparse.ArgumentParser()

parser.add_argument("--repository", type=str, required=True)
parser.add_argument("--manifest", type=str, required=True)

args = parser.parse_args()
repository = args.repository

repo = pygit2.Repository(repository)

submodule_relative_paths = repo.listall_submodules()

submodules_name_and_commit = []

for submodule_relative_path in submodule_relative_paths:
    submodule_info = repo.lookup_submodule(submodule_relative_path)

    submodule_path = pathlib.Path(submodule_relative_path)

    submodule_name = (
        submodule_path.name if submodule_path.name != "src" else submodule_path.parent.name
    )

    # When a submodule gets remove/unregistered from the repository,
    # it's not necessarily removed from the git database,
    # so it might still appear here.
    # We check if the submodule path actually exists.
    if not submodule_path.exists():
        continue

    submodules_name_and_commit.append((submodule_name, submodule_info.head_id.hex))

external_libraries_name_and_version = []

with open(repository + "/libraries/cmake/formula/openssl/CMakeLists.txt") as openssl_cmake:
    match_version = re.compile('OPENSSL_VERSION[\\s]*"(.*)"')

    for line in openssl_cmake:
        match = match_version.search(line)
        if match:
            external_libraries_name_and_version.append(("openssl", match.group(1)))
            break


print("Found the following libraries in the repository:\n")

for name, version in external_libraries_name_and_version:
    print(f"Library {name}, version {version}")

for name, commit in submodules_name_and_commit:
    print(f"Library {name}, commit {commit}")

print("\n\nValidating manifest format and libraries:\n")


manifest_path = args.manifest

manifest = {}
with open(manifest_path, "r") as manifest_file:
    manifest = json.load(manifest_file)

if not validateManifestFormat(manifest):
    exit(1)

if not validateLibrariesVersions(
    manifest, external_libraries_name_and_version, submodules_name_and_commit
):
    exit(1)

print("Done. The manifest is valid")

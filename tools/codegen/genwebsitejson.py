#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

"""
Generate a complete table specification for the website

This script will generate JSON output as expected by the osquery website given
a directory of osquery schema specifications. Results will be printer to stdout.

Usage:
    python tools/codegen/genwebsitejson.py --specs=./specs
"""

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import json
import os
import re
import sys

from gentable import *

# In the specs/ directory of the osquery repository, specification files are put
# in certain directories based on what platforms they are meant to be built on.
# This data structure represents the directories in specs/ and how they map to
# the operating systems which support tables found in those directories
PLATFORM_DIRS = {
    "specs": ["darwin", "linux", "windows"],
    "utility": ["darwin", "linux", "windows"],
    "yara": ["darwin", "linux", "windows"],
    "smart": ["darwin", "linux"],
    "darwin": ["darwin"],
    "kernel": ["darwin"],
    "linwin": ["linux", "windows"],
    "linux": ["linux"],
    "macwin": ["darwin", "windows"],
    "posix": ["darwin", "linux"],
    "sleuthkit": ["darwin", "linux"],
    "windows": ["windows"],
}

BASE_SOURCE_URL = "https://github.com/osquery/osquery/blob/master"

def platform_for_spec(path):
    """Given a path to a table specification, return a list of what osquery
    platforms that table will work on. In the event that no match is found, it
    will be assumed that the table is found on all platforms.
    """
    full_path = os.path.abspath(path)
    directory_list = os.path.dirname(full_path).split("/")
    directory = directory_list[len(directory_list)-1]
    return PLATFORM_DIRS[directory]

def remove_prefix(text, prefix):
    # python 3.9 has `removeprefix`, but I don't want to add that requirement.
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def url_for_spec(specs_dir, path):
    """Given a path to a table specification, return the URL that would take you
    to the specification on GitHub.
    """
    path_fragment = remove_prefix(path, specs_dir).lstrip("/ ")
    url = os.path.join(BASE_SOURCE_URL, "specs", path_fragment)
    return url

def generate_table_metadata(specs_dir, full_path):
    """This function generates a dictionary of table metadata for a spec file
    found at a given path."""
    with open(full_path, "r") as file_handle:
        # Each osquery table specification is a syntactically correct python file
        # because we imported `from gentable import *`, we imported all of the
        # functions that you use in an osquery specification. a global "table"
        # is then modified based on the python that has just executed.
        tree = ast.parse(file_handle.read())
        exec(compile(tree, "<string>", "exec"))

        # Now that the `table` variable is accessible, we can access attributes
        # of the table
        t = {}
        t["name"] = table.table_name
        t["description"] = table.description
        t["url"] = url_for_spec(specs_dir, full_path)
        t["platforms"] = platform_for_spec(full_path)
        t["evented"] = "event_subscriber" in table.attributes
        t["cacheable"] = "cacheable" in table.attributes
        t["notes"] = table.notes
        t["examples"] = table.examples

        # Now we must iterate through `table.columns` to collect information
        # about each column
        t["columns"] = []
        for col in table.columns():
            c = {}
            c["name"] = col.name
            c["description"] = col.description
            c["type"] = col.type.affinity.replace("_TYPE", "").lower()
            c["notes"] = col.notes

            c["hidden"] = col.options.get("hidden", False)
            c["required"] = col.options.get("required", False)
            c["index"] = col.options.get("index", False)
            if col.platforms != []:
                c["platforms"] = col.platforms

            t["columns"].append(c)
    return t

def main(argc, argv):
    parser = argparse.ArgumentParser(
        "Generate minmal JSON from a table spec")
    parser.add_argument("--specs", help="Path to spec directory", required=True)
    args = parser.parse_args()

    specs_dir = os.path.abspath(args.specs)
    tables = {}

    for subdir, dirs, files in os.walk(specs_dir):
        for filename in files:
            # Skip the example spec in the spec/ dir.
            # There is no actual example table in osquery so it should not be generated into the docs.
            if filename == "example.table":
                continue

            if filename.endswith(".table"):
                full_path = os.path.join(subdir, filename)
                metadata = generate_table_metadata(specs_dir, full_path)
                tables[metadata["name"]] = metadata

    # Print the JSON output to stdout
    print(json.dumps([value for key, value in sorted(tables.items())], indent=2, separators=(',', ':')))

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

#!/usr/bin/env python2
"""Generate a complete table specification for the website

This script will generate JSON output as expected by the osquery website given
a directory of osquery schema specifications. Results will be printer to stdout.

Usage:
    python tools/codegen/genwebsitejson.py --specs=./specs
"""

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
    "specs": ["darwin", "linux"],
    "utility": ["darwin", "linux", "freebsd", "windows"],
    "yara": ["darwin", "linux"],
    "darwin": ["darwin"],
    "freebsd": ["freebsd"],
    "kernel": ["darwin"],
    "linux": ["linux"],
    "lldpd": ["linux"],
    "macwin": ["darwin", "windows"],
    "posix": ["darwin", "linux"],
    "sleuthkit": ["darwin", "linux"],
    "windows": ["windows"],
}

def platform_for_spec(path):
    """Given a path to a table specification, return a list of what osquery
    platforms that table will work on. In the event that no match is found, it
    will be assumed that the table is found on all platforms.
    """
    full_path = os.path.abspath(path)
    directory_list = os.path.dirname(full_path).split("/")
    directory = directory_list[len(directory_list)-1]
    try:
        return PLATFORM_DIRS[directory]
    except KeyError:
        return ["darwin", "linux", "freebsd", "windows"]

def url_for_spec(path):
    """Given a path to a table specification, return the URL that would take you
    to the specification on GitHub.
    """
    full_path = os.path.abspath(path)
    url = "https://github.com/facebook/osquery/blob/master"
    osquery_found = False
    for part in full_path.split("/"):
        if osquery_found:
            url = url + "/" + part
        elif part == "osquery":
            osquery_found = True
        else:
            continue
    return url

def generate_table_metadata(full_path):
    """This function generates a dictionary of table metadata for a spec file
    found at a given path."""
    with open(full_path, "rU") as file_handle:
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
        t["url"] = url_for_spec(full_path)
        t["platforms"] = platform_for_spec(full_path)
        t["evented"] = "event_subscriber" in table.attributes
        t["cacheable"] = "cacheable" in table.attributes

        # Now we must iterate through `table.columns` to collect information
        # about each column
        t["columns"] = []
        for col in table.columns():
            c = {}
            c["name"] = col.name
            c["description"] = col.description
            c["type"] = col.type.affinity.replace("_TYPE", "").lower()

            hidden = False
            required = False
            index = False
            for option in col.options:
                if option == "hidden":
                    hidden = True
                elif option == "required":
                    required = True
                elif option == "index":
                    index == True
            c["hidden"] = hidden
            c["required"] = required
            c["index"] = index

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
            if filename.endswith(".table"):
                full_path = os.path.join(subdir, filename)
                metadata = generate_table_metadata(full_path)
                tables[metadata["name"]] = metadata

    # Print the JSON output to stdout
    print(json.dumps([value for key, value in sorted(tables.items())], indent=2, separators=(',', ':')))

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

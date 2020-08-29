#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import json
import os
import sys

try:
    import argparse
except ImportError:
    print("Cannot import argparse.")
    exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "List files from compile_commands.json."
    ))
    parser.add_argument(
        "--build", metavar="PATH",
        help="Path to osquery build (./build/<sys>/) directory"
    )
    parser.add_argument(
        "--base", metavar="PATH", default="",
        help="Real path of source base."
    )

    args = parser.parse_args()

    commands_path = os.path.join(args.build, "compile_commands.json")
    if not os.path.exists(commands_path):
        print("Cannot find '%s'" % (commands_path))
        exit(1)

    with open(commands_path, 'r') as fh: content = fh.read()
    data = json.loads(content)
    for file in data:
        if file['file'].find("_tests.cpp") > 0 or file['file'].find("_benchmark") > 0:
            continue
        if file['file'].find("gtest") > 0:
            continue
        print(file['file'])
        pass

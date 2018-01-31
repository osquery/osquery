#!/usr/bin/env python

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
        print(file['file'].replace(args.base, ""))
        pass
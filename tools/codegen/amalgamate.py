#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import argparse
import os
import sys

import templite

TEMPLATE_NAME = "amalgamation.cpp.in"
BEGIN_LINE = "/// BEGIN[GENTABLE]"
END_LINE = "/// END[GENTABLE]"


def genTableData(filename):
    with open(filename, "r") as fh:
        data = fh.read()
    begin_table = False
    table_data = []
    for line in data.split("\n"):
        if line.find(BEGIN_LINE) >= 0:
            begin_table = True
        elif line.find(END_LINE) >= 0:
            begin_table = False
        elif begin_table:
            table_data.append(line)
    if len(table_data) == 0:
        return None
    return "\n".join(table_data)


def main(argc, argv):
    parser = argparse.ArgumentParser(
        "Generate C++ amalgamation from C++ Table Plugin targets")
    parser.add_argument("--foreign", default=False, action="store_true",
        help="Generate a foreign table set amalgamation")
    parser.add_argument("--templates",
            help="Path to codegen output .cpp.in templates")
    parser.add_argument("--category", help="Category name of generated tables")
    parser.add_argument("--sources",
            help="Path to the folder containing the .cpp files")
    parser.add_argument("--output", help="Path to the output .cpp files")
    args = parser.parse_args()

    tables = []
    # Discover the output template, usually a black cpp file with includes.
    template = os.path.join(args.templates, TEMPLATE_NAME)
    with open(template, "r") as fh:
        template_data = fh.read()

    for base, _, filenames in os.walk(args.sources):
        for filename in filenames:
            if filename == args.category:
                continue
            table_data = genTableData(os.path.join(base, filename))
            if table_data is not None:
                tables.append(table_data)

    amalgamation = templite.Templite(template_data).render(tables=tables,
        foreign=args.foreign)
    try:
        os.makedirs(os.path.dirname(args.output))
    except OSError:
        # Generated folder already exists
        pass
    with open(args.output, "w") as fh:
        fh.write(amalgamation)
    return 0


if __name__ == "__main__":
    exit(main(len(sys.argv), sys.argv))

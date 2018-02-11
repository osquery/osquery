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

import argparse
import jinja2
import os
import sys

# get the platform we are building for
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(SCRIPT_DIR + "/../tests")
from utils import platform
PLATFORM = platform()

TEMPLATE_NAME = "amalgamation.cpp.in"
BEGIN_LINE = "/// BEGIN[GENTABLE]"
END_LINE = "/// END[GENTABLE]"


def genTableData(filename):
    with open(filename, "rU") as fh:
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

gBlacklist=None

class Table(object):
        def __init__(self, name, is_blacklisted):
            self.name = name
            self.is_blacklisted = is_blacklisted

def is_blacklisted(table_name, codegen_path=None):
    """Allow blacklisting by tablename."""
    global gBlacklist
    if gBlacklist is None:
        specs_path = os.path.join(codegen_path, "..", "..", "specs")
        blacklist_path = os.path.join(specs_path, "blacklist")
        if not os.path.exists(blacklist_path):
            return False
        try:
            with open(blacklist_path, "r") as fh:
                gBlacklist = [
                    line.strip() for line in fh.read().split("\n")
                    if len(line.strip()) > 0 and line.strip()[0] != "#"
                ]
        except Exception as e:
            # Blacklist is not readable.
            return False
    if not gBlacklist:
        return False

    # table_name based blacklisting!
    for item in gBlacklist:
        item = item.split(":")
        # If this item is restricted to a platform and the platform
        # and table name match
        if len(item) > 1 and PLATFORM == item[0] and table_name == item[1]:
            return True
        elif len(item) == 1 and table_name == item[0]:
            return True
    return False


def main(argc, argv):
    parser = argparse.ArgumentParser(
        "Generate C++ amalgamation from C++ Table Plugin targets")
    parser.add_argument("--foreign", default=False, action="store_true",
        help="Generate a foreign table set amalgamation")
    parser.add_argument("codegen", help="Path to this codegen folder")
    parser.add_argument("generated", help="Path to generated build folder")
    parser.add_argument("category", help="Category name of generated tables") # utils additional
    parser.add_argument("tablenames", help="space delimited list of table names")
    args = parser.parse_args()

    tables = []
    # Discover the output template, usually a black cpp file with includes.
    template = os.path.join(args.codegen, "templates", TEMPLATE_NAME)
    with open(template, "rU") as fh:
        template_data = fh.read()

    table_names = args.tablenames.split(';')
    for table_name in table_names:
        tables.append(Table(table_name, is_blacklisted(table_name, args.codegen)))

    amalgamation = jinja2.Template(template_data).render(tables=tables,
        foreign=args.foreign, category=args.category)
    output = os.path.join(args.generated, "%s_amalgamation.cpp" % args.category)
    try:
        os.makedirs(os.path.dirname(output))
    except:
        # Generated folder already exists
        pass
    with open(output, "w") as fh:
        fh.write(amalgamation)
    return 0


if __name__ == "__main__":
    exit(main(len(sys.argv), sys.argv))

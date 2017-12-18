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

import ast
import os
import random
import subprocess
import sys

try:
    import argparse
except ImportError:
    print("Cannot import argparse.")
    exit(1)

# Import the testing utils
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../tests/")
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../codegen/")

import utils
from gentable import \
  table_name, schema, description, examples, attributes, implementation, \
  extended_schema, fuzz_paths, \
  WINDOWS, LINUX, POSIX, DARWIN, FREEBSD, \
  Column, ForeignKey, table as TableState, TableState as _TableState, \
  TEXT, DATE, DATETIME, INTEGER, BIGINT, UNSIGNED_BIGINT, DOUBLE, BLOB


def _fuzz_paths(shell, name, paths, query):
    cmd = [
        "zzuf",
        "-r0.001:0.1", "-s%d:%d" % (args.s, args.s + args.n)
    ]
    for path in paths:
        cmd.append("-I")
        cmd.append(path)
    cmd.append(shell)
    cmd.append("--disable_extensions")
    cmd.append(query)
    if args.verbose:
        print (" ".join(cmd))
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    stdout, stderr = proc.communicate()
    if args.verbose:
        print(stdout)
        print(stderr)
    if proc.returncode != 0:
        print (" ".join(cmd))
        print(stderr)
    return proc.returncode

def _fuzz_queries(shell, name, paths, examples=[]):
    print("Fuzzing file reads for: %s" % (name))
    ret = _fuzz_paths(shell, name, paths, "select count(1) from `%s`" % (name))
    if ret != 0:
        return ret
    for example in examples:
        print("Fuzzing file reads for query: %s" % (example))
        ret = _fuzz_paths(shell, name, paths, example)
        if ret != 0:
            return ret
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "Search table specs for opt-in fuzzing options"
    ))
    parser.add_argument(
        "--specs", metavar="PATH", default="./specs",
        help="Path to the osquery table specs."
    )
    parser.add_argument(
        "--table", metavar="TABLE", default="",
        help="Restrict to a single table"
    )
    parser.add_argument(
        "--verbose", action="store_true", default=False,
        help="Be verbose."
    )
    parser.add_argument(
        "-c", action="store_true", default=False,
        help="Continue working event if a crash is detected."
    )
    parser.add_argument(
        "-n", type=int, default=20,
        help="Number of seeds"
    )
    parser.add_argument(
        "-s", type=int, default=-1,
        help="Initial seed"
    )

    group = parser.add_argument_group("Run Options:")
    group.add_argument(
        "--shell", metavar="PATH", default="./build/%s/osquery/osqueryi" % (
            utils.platform()),
        help="Path to osqueryi shell (./build/<sys>/osquery/osqueryi)."
    )

    args = parser.parse_args()
    if not os.path.exists(args.shell):
        print("Cannot find --shell: %s" % (args.shell))
        exit(1)
    if not os.path.exists(args.specs):
        print("Cannot find --specs: %s" % (args.specs))
        exit(1)

    if args.s < 0:
        args.s = random.randint(0, 65535)

    exit_code = 0
    tables = utils.queries_from_tables(args.specs, args.table)
    for table in tables:
        table = table.split(".")
        if table[0] == "specs":
            table.pop(0)
        table[-1] += ".table"

        filename = os.path.join(args.specs, *table)
        with open(filename, 'rU') as fh:
            # Open and parse/execute the specification.
            tree = ast.parse(fh.read())
            TableState = _TableState()
            exec(compile(tree, "<string>", "exec"))

            # We may later introduce other (simple) types of fuzzing.
            if len(TableState.fuzz_paths) > 0:
                # The table specification opted-into path-based fuzzing.
                ret = _fuzz_queries(args.shell, TableState.table_name,
                    TableState.fuzz_paths, TableState.examples)
                if ret > 0:
                    exit_code = ret
                if not args.c and ret != 0:
                    break
    sys.exit(exit_code)

#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# The cppcheck job (check_source_code) configures the project and runs
# prepare_for_ide, but does not perform a full build. Generated sources (e.g.
# protobuf/gRPC .pb.cc) are therefore absent, yet still listed in
# compile_commands.json. cppcheck validates every entry at project-load time, so
# a missing generated file aborts the whole run before analysis begins. Write a
# filtered copy of the compilation database that keeps only entries whose source
# is actually present; the dropped sources are generated code cppcheck would not
# analyze anyway.

import json
import os
import sys


def main():
    if len(sys.argv) != 3:
        print(
            "usage: filter_compile_commands.py <input.json> <output.json>",
            file=sys.stderr,
        )
        return 1

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path) as input_file:
        entries = json.load(input_file)

    kept = [entry for entry in entries if os.path.exists(entry["file"])]
    dropped = [entry["file"] for entry in entries if not os.path.exists(entry["file"])]

    with open(output_path, "w") as output_file:
        json.dump(kept, output_file)

    if dropped:
        print(
            "cppcheck: skipping "
            + str(len(dropped))
            + " compile-database entries whose source is not present "
            + "(generated, not built in this step):"
        )
        for path in dropped:
            print("  " + path)

    return 0


if __name__ == "__main__":
    sys.exit(main())

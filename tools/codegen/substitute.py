#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

"""
Replace every occurrences of pattern in every string of input file and write it in output
"""

import argparse
import re
import sys


def main(args):
    r = re.compile(args.pattern)
    for line in args.infile:
        args.outfile.write(
            r.sub(args.replacement, line)
        )
        args.outfile.write('\n')


def parse_args():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "-i",
        "--infile",
        type=argparse.FileType('r'),
        default=sys.stdin,
        help="Input file",
    )
    parser.add_argument(
        "-o",
        "--outfile",
        type=argparse.FileType('w'),
        default=sys.stdout,
        help="Output file",
    )
    parser.add_argument(
        "--pattern",
        required=True,
        help="Regexp pattern to search",
    )
    parser.add_argument(
        "--replacement",
        required=True,
        help="Replacement for matched string",
    )
    return parser.parse_args()


def run():
    args = parse_args()
    main(args)


if __name__ == "__main__":
    run()

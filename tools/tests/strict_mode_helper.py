#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

"""
A script to help you generate signatures for queries and protected tables
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import hashlib
import argparse
import base64
import os

import ecdsa

if __name__ == '__main__':
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    PARSER = argparse.ArgumentParser(description=(
        "osquery python strict mode helper"
    ))

    PARSER.add_argument(
        "--ptables", default="", type=str,
        help="A comma delimited list of types that require a signature"
    )

    PARSER.add_argument(
        "--sign", default="", type=str,
        help="Sign a single query (for use in scheduled systems)"
    )

    PARSER.add_argument(
        "--key", metavar="PRIVATE_KEY_FILE",
        default=SCRIPT_DIR + "/strict_test_key.pem",
        help="The private key to use for signing"
    )
    ARGS = PARSER.parse_args()
    SK = None
    with open(ARGS.key, "r") as fh:
        SK = ecdsa.SigningKey.from_pem(fh.read())

    if ARGS.ptables:
        # Table lists always end in a comma unless there are no tables
        print(
            base64.standard_b64encode(
                SK.sign(
                    ARGS.ptables,
                    hashfunc=hashlib.sha256,
                    sigencode=ecdsa.util.sigencode_der
                    )
                )
            )
    elif ARGS.sign:
        print(
            base64.standard_b64encode(
                SK.sign(
                    ARGS.sign,
                    hashfunc=hashlib.sha256,
                    sigencode=ecdsa.util.sigencode_der
                    )
                )
            )

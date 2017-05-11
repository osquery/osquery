#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ecdsa
import hashlib
import argparse
import base64
import json
import os
import random
import ssl
import string
import sys 
import thread
import threading

def protected_tables_sig():
	pass

def sign_a_query():
	pass

if __name__ == '__main__':
	SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
	parser = argparse.ArgumentParser(description=(
		"osquery python strict mode helper"
	))

	parser.add_argument(
		"--ptables", default="", type=str,
		help="A comma delimited list of types that require a signature"
	)

	parser.add_argument(
		"--sign", default="", type=str,
		help="Sign a single query (for use in scheduled systems)"
	)

	parser.add_argument(
        "--key", metavar="PRIVATE_KEY_FILE",
        default=SCRIPT_DIR + "/strict_test_key.pem",
        help="The private key to use for signing"
    )
	ARGS = parser.parse_args()
	sk = None
	with open(ARGS.key, "r") as fh:
		sk = ecdsa.SigningKey.from_pem(fh.read())

	if len(ARGS.ptables):
		# Table lists always end in a comma unless there are no tables
		print(base64.standard_b64encode(sk.sign(ARGS.ptables, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)))
	elif len(ARGS.sign):
		print(base64.standard_b64encode(sk.sign(ARGS.sign, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)))

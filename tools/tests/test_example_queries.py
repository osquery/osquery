#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import json
import os
import shutil
import time
import unittest
import sys

# osquery-specific testing utils
import test_base
import utils


class ExampleQueryTests(test_base.QueryTester):
    def test_cross_platform_queries(self):
        self._execute_set(PLATFORM_EXAMPLES["specs"])

    def test_platform_specific_queries(self):
        posix = ["darwin", "linux"]
        if utils.platform() in posix:
            self._execute_set(PLATFORM_EXAMPLES["posix"])
        self._execute_set(PLATFORM_EXAMPLES[utils.platform()])

    def test_utility_queries(self):
        self._execute_set(PLATFORM_EXAMPLES["utility"])

if __name__ == '__main__':
    # Import the API generation code for example query introspection.
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    SOURCE_DIR = os.path.abspath(SCRIPT_DIR + "/../../")
    sys.path.append(SOURCE_DIR + "/tools/codegen")
    from genapi import gen_api
    API = gen_api(SOURCE_DIR + "/specs")

    # Organize example queries by platform
    PLATFORM_EXAMPLES = {}
    for category in API:
        PLATFORM_EXAMPLES[category["key"]] = []
        for table in category["tables"]:
            if len(table["examples"]) > 0:
                PLATFORM_EXAMPLES[category["key"]] += table["examples"]
            else:
                PLATFORM_EXAMPLES[category["key"]] += [
                    "select * from %s limit 1" % table["name"]
                ]

    module = test_base.Tester()

    # Find and import the thrift-generated python interface
    test_base.loadThriftFromBuild(test_base.ARGS.build)

    module.run()

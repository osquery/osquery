#!/usr/bin/env python3

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

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
    @test_base.flaky
    def test_cross_platform_queries(self):
        self._execute_set(PLATFORM_EXAMPLES["specs"])

    @test_base.flaky
    def test_platform_specific_queries(self):
        posix = ["darwin", "linux"]
        if utils.platform() in posix:
            self._execute_set(PLATFORM_EXAMPLES["posix"])
        self._execute_set(PLATFORM_EXAMPLES[utils.platform()])

    @test_base.flaky
    def test_utility_queries(self):
        self._execute_set(PLATFORM_EXAMPLES["utility"])

if __name__ == '__main__':
    module = test_base.Tester()

    # Import the API generation code for example query introspection.
    from genapi import gen_api
    API = gen_api("%s/specs" % (test_base.TEST_CONFIGS_DIR))

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

    # Find and import the thrift-generated python interface
    test_base.loadThriftFromBuild(test_base.ARGS.build)

    module.run()

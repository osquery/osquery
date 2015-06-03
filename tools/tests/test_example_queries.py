#!/usr/bin/env python

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import shutil
import time
import unittest
import sys

# osquery-specific testing utils
import test_base
import utils

class ExampleQueryTests(test_base.ProcessGenerator, unittest.TestCase):
    def setUp(self):
        self.daemon = self._run_daemon({
            # The set of queries will hammer the daemon process.
            "disable_watchdog": True,
        })
        self.assertTrue(self.daemon.isAlive())

        # The sets of example tests will use the extensions API.s
        self.client = test_base.EXClient(self.daemon.options["extensions_socket"])
        test_base.expectTrue(self.client.open)
        self.assertTrue(self.client.open())
        self.em = self.client.getEM()

    def tearDown(self):
        self.client.close()
        self.daemon.kill()

    def _execute(self, query):
        try:
            result = self.em.query(query)
            self.assertEqual(result.status.code, 0)
            return result.response
        except Exception as e:
            print("General exception executing query: %s" % (
                utils.lightred(query)))
            raise e

    def _execute_set(self, queries):
        for example in queries:
            start_time = time.time()
            result = self._execute(example)
            end_time = time.time()
            duration_ms = int((end_time - start_time) * 1000)
            if duration_ms > 2000:
                # Query took longer than 2 seconds.
                duration_ms = utils.lightred(duration_ms)
            print("Query (%sms): %s, rows: %d" % (
                duration_ms, example, len(result)))


    def test_cross_platform_queries(self):
        self._execute_set(PLATFORM_EXAMPLES["specs"])

    def test_platform_specific_queries(self):
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
            PLATFORM_EXAMPLES[category["key"]] += table["examples"]

    module = test_base.Tester()

    # Find and import the thrift-generated python interface
    test_base.loadThriftFromBuild(test_base.ARGS.build)

    module.run()

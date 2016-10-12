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
# pyexpect.replwrap will not work with unicode_literals
# from __future__ import unicode_literals

import os
import sys
import unittest

# osquery-specific testing utils
import test_base
import utils


class ModuleTests(test_base.ProcessGenerator, unittest.TestCase):

    def setUp(self):
        self.binary = os.path.join(test_base.ARGS.build, "osquery", "osqueryi")
        ext = "dylib" if sys.platform == "darwin" else "so"
        self.modules_loader = test_base.Autoloader(
            [test_base.ARGS.build + "/osquery/libmodexample.%s" % ext])
        self.osqueryi = test_base.OsqueryWrapper(self.binary,
                                                 {"modules_autoload": self.modules_loader.path})

    def test_1_shell_with_module(self):
        '''Test the shell loads the compiled shared library.'''
        self.osqueryi.run_command(' ')
        result = self.osqueryi.run_query('SELECT * from example')
        self.assertEqual(len(result), 1)

    def test_2_shell_list_modules(self):
        '''Test the modules/extensions table.'''
        self.osqueryi.run_command(' ')
        result = self.osqueryi.run_query(
            'SELECT * from osquery_extensions '
            'where type = "module" and name = "example"')
        self.assertEqual(len(result), 1)

    def test_3_module_prevent_create(self):
        '''Test a failed module create (we interrupt the static construction).
        This test uses a special environment variable checked in the example
        module built as part of the default SDK build.
        '''
        self.osqueryi = test_base.OsqueryWrapper(self.binary,
                                                 {"modules_autoload": self.modules_loader.path}, {"TESTFAIL1": "1"})
        result = self.osqueryi.run_query(
            'SELECT * from time;')
        # Make sure the environment variable did not introduce any unexpected
        # crashes with the unit or integration tests.
        self.assertEqual(len(result), 1)
        # The environment variable should have prevented the module load.
        self.assertRaises(test_base.OsqueryException,
                          self.osqueryi.run_query, 'SELECT * from example;')

    def test_4_module_prevent_initialize(self):
        '''Test a failed module initialize (we interrupt the registry call).
        '''
        self.osqueryi = test_base.OsqueryWrapper(self.binary,
                                                 {"modules_autoload": self.modules_loader.path}, {"TESTFAIL2": "1"})
        # The environment variable should have prevented the module load.
        self.assertRaises(test_base.OsqueryException,
                          self.osqueryi.run_query, 'SELECT * from example;')


if __name__ == "__main__":
    test_base.assertPermissions()
    module = test_base.Tester().run()

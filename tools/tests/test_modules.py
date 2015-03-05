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
# pyexpect.replwrap will not work with unicode_literals
#from __future__ import unicode_literals

import os
import unittest

# osquery-specific testing utils
import test_base

class ModuleTests(test_base.ProcessGenerator, unittest.TestCase):
    def setUp(self):
        binary = os.path.join(test_base.ARGS.build, "osquery", "osqueryi")
        self.modules_path = os.path.join(test_base.ARGS.build, "osquery")
        self.osqueryi = test_base.OsqueryWrapper(binary,
            {"modules_autoload": self.modules_path})

    def test_1_shell_with_module(self):
        '''Test the shell loads the compiled shared library.'''
        self.osqueryi.run_command(' ')
        result = self.osqueryi.run_query('SELECT * from example;')
        self.assertEqual(len(result), 1)

    def test_2_shell_list_modules(self):
        '''Test the modules/extensions table.'''
        self.osqueryi.run_command(' ')
        result = self.osqueryi.run_query(
            'SELECT * from osquery_extensions where type = "module" and name = "example";')
        self.assertEqual(len(result), 1)

if __name__ == "__main__":
    module = test_base.Tester().run()

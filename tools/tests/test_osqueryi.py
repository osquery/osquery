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
import random
import unittest

# osquery-specific testing utils
import test_base

SHELL_TIMEOUT = 10

class OsqueryiTest(unittest.TestCase):
    def setUp(self):
        self.binary = os.path.join(test_base.ARGS.build, "osquery", "osqueryi")
        self.osqueryi = test_base.OsqueryWrapper(self.binary)
        self.dbpath = "%s%s" % (
            test_base.CONFIG["options"]["database_path"],
            str(random.randint(1000, 9999)))

    def test_error(self):
        '''Test that we throw an error on bad query'''
        self.osqueryi.run_command(' ')
        self.assertRaises(test_base.OsqueryException,
            self.osqueryi.run_query, 'foo')

    def test_config_check_success(self):
        '''Test that a 0-config passes'''
        proc = test_base.TimeoutRunner([
                self.binary,
                "--config_check",
                "--database_path=%s" % (self.dbpath),
                "--config_path=%s/test.config" % test_base.SCRIPT_DIR
            ],
            SHELL_TIMEOUT)
        self.assertEqual(proc.stdout, "")
        print (proc.stdout)
        print (proc.stderr)
        self.assertEqual(proc.proc.poll(), 0)

    def test_config_check_failure(self):
        '''Test that a missing config fails'''
        proc = test_base.TimeoutRunner([
            self.binary,
                "--config_check",
                "--database_path=%s" % (self.dbpath),
                "--config_path=/this/path/does/not/exist"
            ],
            SHELL_TIMEOUT)
        self.assertNotEqual(proc.stderr, "")
        print (proc.stdout)
        print (proc.stderr)
        self.assertEqual(proc.proc.poll(), 1)

        # Now with a valid path, but invalid content.
        proc = test_base.TimeoutRunner([
                self.binary,
                "--config_check",
                "--database_path=%s" % (self.dbpath),
                "--config_path=%s/test.badconfig" % test_base.SCRIPT_DIR
            ],
            SHELL_TIMEOUT)
        self.assertEqual(proc.proc.poll(), 1)
        self.assertNotEqual(proc.stderr, "")

        # Finally with a missing config plugin
        proc = test_base.TimeoutRunner([
                self.binary,
                "--config_check",
                "--database_path=%s" % (self.dbpath),
                "--config_plugin=does_not_exist"
            ],
            SHELL_TIMEOUT)
        self.assertNotEqual(proc.stderr, "")
        self.assertNotEqual(proc.proc.poll(), 0)

    def test_meta_commands(self):
        '''Test the supported meta shell/help/info commands'''
        commands = [
            '.help',
            '.all',
            '.all osquery_info',
            '.all this_table_does_not_exist',
            '.echo',
            '.echo on',
            '.echo off',
            '.header',
            '.header off',
            '.header on',
            '.mode',
            '.mode csv',
            '.mode column',
            '.mode line',
            '.mode list',
            '.mode pretty',
            '.mode this_mode_does_not_exists',
            '.nullvalue',
            '.nullvalue ""',
            '.print',
            '.print hello',
            '.schema osquery_info',
            '.schema this_table_does_not_exist',
            '.schema',
            '.separator',
            '.separator ,',
            '.show',
            '.tables osquery',
            '.tables osquery_info',
            '.tables this_table_does_not_exist',
            '.tables',
            '.trace',
            '.width',
            '.width 80',
            '.timer',
            '.timer on',
            '.timer off'
        ]
        for command in commands:
            result = self.osqueryi.run_command(command)
        pass

    def test_time(self):
        '''Demonstrating basic usage of OsqueryWrapper with the time table'''
        self.osqueryi.run_command(' ')  # flush error output
        result = self.osqueryi.run_query(
            'SELECT hour, minutes, seconds FROM time;')
        self.assertEqual(len(result), 1)
        row = result[0]
        self.assertTrue(0 <= int(row['hour']) <= 24)
        self.assertTrue(0 <= int(row['minutes']) <= 60)
        self.assertTrue(0 <= int(row['seconds']) <= 60)

    def test_config_bad_json(self):
        self.osqueryi = test_base.OsqueryWrapper(self.binary,
            args={"config_path": "/"})
        result = self.osqueryi.run_query('SELECT * FROM time;')
        self.assertEqual(len(result), 1)

if __name__ == '__main__':
    test_base.Tester().run()

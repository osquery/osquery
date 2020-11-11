#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import os
import random
import sys
import unittest
import utils

# osquery-specific testing utils
import test_base

SHELL_TIMEOUT = 10
EXIT_CATASTROPHIC = 78


def configFile(config_name):
    return os.path.join(test_base.TEST_CONFIGS_DIR, config_name)


class OsqueryiTest(unittest.TestCase):
    def setUp(self):
        self.binary = test_base.getLatestOsqueryBinary('osqueryi')
        self.osqueryi = test_base.OsqueryWrapper(command=self.binary)

    @unittest.skipIf(os.name == "nt", "stderr tests not supported on Windows.")
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
            "--config_path=%s" % configFile("test.config"),
            "--verbose",
        ],
            SHELL_TIMEOUT)
        self.assertEqual(proc.stdout, b"")
        print(proc.stdout)
        print(proc.stderr)
        self.assertEqual(proc.proc.poll(), 0)

    def test_config_dump(self):
        '''Test that config raw output is dumped when requested'''
        config = configFile("test_noninline_packs.conf")
        proc = test_base.TimeoutRunner([
                self.binary,
                "--config_dump",
                "--config_path=%s" % config,
                "--verbose",
            ],
            SHELL_TIMEOUT)
        content = ""
        with open(config, 'r') as fh:
            content = fh.read()
        actual = proc.stdout.decode('utf-8')

        if os.name == "nt":
            actual = actual.replace('\r', '')

        self.assertEqual(actual, '{"%s": %s}\n' % (config, content))
        print (proc.stderr)
        self.assertEqual(proc.proc.poll(), 0)

    def test_config_check_failure_invalid_path(self):
        '''Test that a missing config fails'''
        proc = test_base.TimeoutRunner([
            self.binary,
            "--config_check",
            "--verbose",
            "--config_path=/this/path/does/not/exist"
        ],
            SHELL_TIMEOUT)
        self.assertNotEqual(proc.stderr, "")
        print(proc.stdout)
        print(proc.stderr)
        self.assertEqual(proc.proc.poll(), 1)

    def test_config_check_failure_valid_path(self):
        # Now with a valid path, but invalid content.
        proc = test_base.TimeoutRunner([
            self.binary,
            "--config_check",
            "--verbose",
            "--config_path=%s" % configFile("test.badconfig"),
        ],
            SHELL_TIMEOUT)
        self.assertEqual(proc.proc.poll(), 1)
        self.assertNotEqual(proc.stderr, "")

    def test_config_check_failure_missing_plugin(self):
        # Finally with a missing config plugin
        proc = test_base.TimeoutRunner([
            self.binary,
            "--config_check",
            "--verbose",
            "--config_plugin=does_not_exist"
        ],
            SHELL_TIMEOUT)
        self.assertNotEqual(proc.stderr, "")
        self.assertNotEqual(proc.proc.poll(), 0)
        # Also do not accept a SIGSEG
        self.assertEqual(proc.proc.poll(), EXIT_CATASTROPHIC)

    def test_config_check_example(self):
        '''Test that the example config passes'''
        proc = test_base.TimeoutRunner([
                self.binary,
                "--config_check",
                "--config_path=%s" % configFile("osquery.example.conf"),
                "--verbose",
            ],
            SHELL_TIMEOUT)
        self.assertEqual(proc.stdout, b"")
        print (proc.stdout)
        print (proc.stderr)
        self.assertEqual(proc.proc.poll(), 0)

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

    def test_json_output(self):
        '''Test that the output of --json is valid json'''
        proc = test_base.TimeoutRunner([
            self.binary,
            "select 0",
            "--json",
            ],
            SHELL_TIMEOUT
        )
        if os.name == "nt":
            self.assertEqual(proc.stdout, b"[\r\n  {\"0\":\"0\"}\r\n]\r\n")
        else:
            self.assertEqual(proc.stdout, b"[\n  {\"0\":\"0\"}\n]\n")
        print(proc.stdout)
        print(proc.stderr)
        self.assertEqual(proc.proc.poll(), 0)

    def test_json_pretty_output(self):
        '''Test that the output of --json_pretty is valid json'''
        proc = test_base.TimeoutRunner([
            self.binary,
            "select 0",
            "--json_pretty",
        ],
            SHELL_TIMEOUT
        )
        if os.name == "nt":
            self.assertEqual(
                proc.stdout, b"[\r\n  {\r\n    \"0\": \"0\"\r\n  }\r\n]\r\n")
        else:
            self.assertEqual(
                proc.stdout, b"[\n  {\n    \"0\": \"0\"\n  }\n]\n")
        print(proc.stdout)
        print(proc.stderr)
        self.assertEqual(proc.proc.poll(), 0)

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

    # TODO: Running foreign table tests as non-priv user fails
    @unittest.skipIf(os.name == "nt", "foreign table tests not supported on Windows.")
    def test_foreign_tables(self):
        '''Requires the --enable_foreign flag to add at least one table.'''
        self.osqueryi.run_command(' ')

        query = 'SELECT count(1) c FROM osquery_registry;'
        result = self.osqueryi.run_query(query)
        before = int(result[0]['c'])

        osqueryi2 = test_base.OsqueryWrapper(self.binary,
            args={"enable_foreign": True})
        osqueryi2.run_command(' ')
        # This execution fails if the user is not Administrator on Windows
        result = osqueryi2.run_query(query)
        after = int(result[0]['c'])
        self.assertGreater(after, before)

    def test_time_using_all(self):
        self.osqueryi.run_command(' ')
        result = self.osqueryi.run_command('.all time')
        self.assertNotEqual(result.rstrip(), "Error querying table: time")

    def test_config_bad_json(self):
        self.osqueryi = test_base.OsqueryWrapper(self.binary,
                                                 args={"config_path": "/"})
        result = self.osqueryi.run_query('SELECT * FROM time;')
        self.assertEqual(len(result), 1)

    def test_atc(self):
        local_osquery_instance = test_base.OsqueryWrapper(self.binary,
                                                 args={"config_path": "test.config"})
        result = local_osquery_instance.run_query('SELECT a_number FROM test_atc')
        self.assertEqual(result, [{'a_number':'314159'}])

if __name__ == '__main__':
    with test_base.CleanChildProcesses():
        test_base.Tester().run()

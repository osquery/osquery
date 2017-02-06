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

import os
import signal
import shutil
import time
import unittest

# osquery-specific testing utils
import test_base


class DaemonTests(test_base.ProcessGenerator, unittest.TestCase):
    @test_base.flaky
    def test_1_daemon_without_watchdog(self):
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
        })
        self.assertTrue(daemon.isAlive())
        daemon.kill()

    @test_base.flaky
    def test_2_daemon_with_option(self):
        logger_path = test_base.getTestDirectory(test_base.CONFIG_DIR)
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
            "disable_logging": False,
        },
            options_only={
            "logger_path": logger_path,
            "verbose": True,
        })
        info_path = os.path.join(logger_path, "osqueryd.INFO")
        self.assertTrue(daemon.isAlive())

        def info_exists():
            return os.path.exists(info_path)
        # Wait for the daemon to flush to GLOG.
        test_base.expectTrue(info_exists)
        self.assertTrue(os.path.exists(info_path))
        daemon.kill()

    @test_base.flaky
    def test_3_daemon_with_watchdog(self):
        # This test does not join the service threads properly (waits for int).
        if os.environ.get('SANITIZE') is not None:
            return
        daemon = self._run_daemon({
            "disable_watchdog": False,
            "ephemeral": True,
            "disable_database": True,
            "disable_logging": True,
        })
        self.assertTrue(daemon.isAlive())

        # Check that the daemon spawned a child process
        children = daemon.getChildren()
        self.assertTrue(len(children) > 0)
        daemon.kill()

        # This will take a few moments to make sure the client process
        # dies when the watcher goes away
        self.assertTrue(daemon.isDead(children[0]))

    @test_base.flaky
    def test_4_daemon_sighup(self):
        # A hangup signal should not do anything to the daemon.
        daemon = self._run_daemon({
            "disable_watchdog": True,
        })
        self.assertTrue(daemon.isAlive())

        # Send a SIGHUP
        os.kill(daemon.proc.pid, signal.SIGHUP)
        self.assertTrue(daemon.isAlive())

    @test_base.flaky
    def test_5_daemon_sigint(self):
        # An interrupt signal will cause the daemon to stop.
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "ephemeral": True,
            "disable_database": True,
            "disable_logging": True,
        })
        self.assertTrue(daemon.isAlive())

        # Send a SIGINT
        os.kill(daemon.pid, signal.SIGINT)
        self.assertTrue(daemon.isDead(daemon.pid, 10))
        self.assertTrue(daemon.retcode in [128 + signal.SIGINT, -2])

    @test_base.flaky
    def test_6_logger_mode(self):
        logger_path = test_base.getTestDirectory(test_base.CONFIG_DIR)
        test_mode = 0754        # Strange mode that should never exist
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
            "disable_logging": False,
        },
        options_only={
            "logger_path": logger_path,
            "logger_mode": test_mode,
            "verbose": True,
        })
        info_path = os.path.join(logger_path, "osqueryd.INFO")
        results_path = os.path.join(logger_path, "osqueryd.results.log")
        self.assertTrue(daemon.isAlive())

        def info_exists():
            return os.path.exists(info_path)
        def results_exists():
            return os.path.exists(results_path)

        # Wait for the daemon to flush to GLOG.
        test_base.expectTrue(info_exists)
        test_base.expectTrue(results_exists)

        # Both log files should exist, the results should have the given mode.
        for pth in [info_path, results_path]:
            self.assertTrue(os.path.exists(pth))

            # Only apply the mode checks to .log files.
            if pth.find('.log') > 0:
                rpath = os.path.realpath(pth)
                mode = os.stat(rpath).st_mode & 0777
                self.assertEqual(mode, test_mode)

        daemon.kill()

    def test_7_logger_stdout(self):
        logger_path = test_base.getTestDirectory(test_base.CONFIG_DIR)
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
            "disable_logging": False,
            "logger_plugin": "stdout",
            "logger_path": logger_path,
            "verbose": True,
        })

        info_path = os.path.join(logger_path, "osqueryd.INFO")
        def pathDoesntExist():
            if os.path.exists(info_path):
                return False
            return True
        self.assertTrue(daemon.isAlive())
        self.assertTrue(pathDoesntExist())
        daemon.kill()


if __name__ == '__main__':
    test_base.Tester().run()

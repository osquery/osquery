#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import glob
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
        logger_path = test_base.getTestDirectory(test_base.TEMP_DIR)
        daemon = self._run_daemon(
            {
                "disable_watchdog": True,
                "disable_extensions": True,
                "disable_logging": False,
            },
            options_only={
                "logger_path": logger_path,
                "verbose": True,
            })

        self.assertTrue(daemon.isAlive())

        info_path = os.path.join(logger_path, "osqueryd.INFO*")
        def info_exists():
            return len(glob.glob(info_path)) > 0

        # Wait for the daemon to flush to GLOG.
        test_base.expectTrue(info_exists)

        # Assign the variable after we have assurances it exists
        self.assertTrue(info_exists())

        # Lastly, verify that we have permission to read the file
        data = ''
        with open(glob.glob(info_path)[0], 'r') as fh:
            try:
                data = fh.read()
            except:
                pass
        self.assertTrue(len(data) > 0)
        daemon.kill()

    @test_base.flaky
    def test_3_daemon_with_watchdog(self):
        # This test does not join the service threads properly (waits for int).
        if os.environ.get('SANITIZE') is not None:
            return
        daemon = self._run_daemon({
            "allow_unsafe": True,
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
    def test_3_daemon_lost_worker(self):
        # Test that killed workers are respawned by the watcher
        if os.environ.get('SANITIZE') is not None:
            return
        daemon = self._run_daemon({
            "allow_unsafe": True,
            "disable_watchdog": False,
            "ephemeral": True,
            "disable_database": True,
            "disable_logging": True,
        })
        self.assertTrue(daemon.isAlive())

        # Check that the daemon spawned a child process
        children = daemon.getChildren()
        self.assertTrue(len(children) > 0)

        # Kill only the child worker
        os.kill(children[0], signal.SIGINT)
        self.assertTrue(daemon.isDead(children[0]))
        self.assertTrue(daemon.isAlive())

        # Expect the children of the daemon to be respawned
        def waitDaemonChildren():
            children = daemon.getChildren()
            return len(children) > 0
        test_base.expectTrue(waitDaemonChildren)
        children = daemon.getChildren()
        self.assertTrue(len(children) > 0)

    @test_base.flaky
    def test_4_daemon_sighup(self):
        # A hangup signal should not do anything to the daemon.
        daemon = self._run_daemon({
            "disable_watchdog": True,
        })
        self.assertTrue(daemon.isAlive())

        # Send SIGHUP on posix. Windows does not have SIGHUP so we use SIGTERM
        sig = signal.SIGHUP if os.name != "nt" else signal.SIGTERM
        os.kill(daemon.proc.pid, sig)
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
        if os.name != "nt":
            self.assertEqual(daemon.retcode, 0)

    @test_base.flaky
    def test_6_logger_mode(self):
        logger_path = test_base.getTestDirectory(test_base.TEMP_DIR)
        test_mode = 0o754  # Strange mode that should never exist
        daemon = self._run_daemon(
            {
                "disable_watchdog": True,
                "disable_extensions": True,
                "disable_logging": False,
            },
            options_only={
                "logger_path": logger_path,
                "logger_mode": test_mode,
                "verbose": True,
            },
        )

        self.assertTrue(daemon.isAlive())

        # Wait for the daemon to write the info log to disk before continuing
        info_path = os.path.join(logger_path, "osqueryd.INFO*")
        def info_exists():
            return len(glob.glob(info_path)) > 0

        results_path = os.path.join(logger_path, "osqueryd.results.log")
        def results_exists():
            return os.path.exists(results_path)

        # Wait for the daemon to flush to GLOG.
        test_base.expectTrue(info_exists)
        test_base.expectTrue(results_exists)

        info_path = glob.glob(info_path)[0]
        # Both log files should exist, the results should have the given mode.
        for pth in [info_path, results_path]:
            self.assertTrue(os.path.exists(pth))

            # Only apply the mode checks to .log files.
            # TODO: Add ACL checks for Windows logs
            if pth.find('.log') > 0 and os.name != "nt":
                rpath = os.path.realpath(pth)
                mode = os.stat(rpath).st_mode & 0o777
                self.assertEqual(mode, test_mode)

        daemon.kill()

    def test_7_logger_stdout(self):
        logger_path = test_base.getTestDirectory(test_base.TEMP_DIR)
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

    def test_8_hostid_uuid(self):
        # Test added to test using UUID as hostname ident for issue #3195
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
            "disable_logging": False,
            "logger_plugin": "stdout",
            "host_identifier": "uuid",
            "verbose": True,
        })

        self.assertTrue(daemon.isAlive())
        daemon.kill()

    def test_9_hostid_instance(self):
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
            "disable_logging": False,
            "logger_plugin": "stdout",
            "host_identifier": "instance",
            "verbose": True,
        })

        self.assertTrue(daemon.isAlive())
        daemon.kill()

    def test_config_check_exits(self):
        daemon = self._run_daemon(
            {
                "config_check": True,
                "disable_extensions": True,
                "disable_logging": False,
                "disable_database": True,
                "logger_plugin": "stdout",
                "verbose": True,
            },
            options_only={
                "verbose": True,
            },
        )

        self.assertTrue(daemon.isDead(daemon.pid, 10))
        if os.name != "nt":
            self.assertEqual(daemon.retcode, 0)

    def test_config_dump_exits(self):
        daemon = self._run_daemon(
            {
                "config_dump": True,
                "disable_extensions": True,
                "disable_logging": False,
                "disable_database": True,
                "logger_plugin": "stdout",
                "verbose": True,
            },
            options_only={
                "verbose": True,
            },
        )

        self.assertTrue(daemon.isDead(daemon.pid, 10))
        if os.name != "nt":
            self.assertEqual(daemon.retcode, 0)

    def test_database_dump_exits(self):
        daemon = self._run_daemon({
            "database_dump": True,
            "disable_extensions": True,
            "disable_logging": False,
            "disable_database": True,
            "logger_plugin": "stdout",
            "verbose": True,
        })

        self.assertTrue(daemon.isDead(daemon.pid, 10))
        if os.name != "nt":
            self.assertEqual(daemon.retcode, 0)

if __name__ == '__main__':
    with test_base.CleanChildProcesses():
        test_base.Tester().run()

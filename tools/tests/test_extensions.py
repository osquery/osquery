#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import glob
import os
import psutil
import signal
import subprocess
import sys
import time
import threading
import unittest

# osquery-specific testing utils
import test_base
import utils

EXTENSION_TIMEOUT = 10


class ExtensionTests(test_base.ProcessGenerator, unittest.TestCase):
    def test_daemon_without_extensions(self):
        # Start the daemon without thrift, prefer no watchdog because the tests
        # kill the daemon very quickly.
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
        })
        self.assertTrue(daemon.isAlive())

        # Now try to connect to the disabled API
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertFalse(client.open())
        daemon.kill()

    def test_daemon_api(self):
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # List the number of extensions
        print(em.ping())
        result = test_base.expect(em.extensions, 0)
        self.assertEqual(len(result), 0)

        # Try the basic ping API
        self.assertEqual(em.ping().code, 0)

        # Try a query
        response = em.query("select * from time")
        self.assertEqual(response.status.code, 0)
        self.assertEqual(len(response.response), 1)
        self.assertTrue("seconds" in response.response[0].keys())

        # Try to get the query columns
        response = em.getQueryColumns("select seconds as s from time")
        self.assertEqual(response.status.code, 0)
        self.assertEqual(len(response.response), 1)
        self.assertTrue("s" in response.response[0])
        client.close()
        daemon.kill()

    def test_example_extension(self):
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # Make sure there are no extensions registered
        result = test_base.expect(em.extensions, 0)
        self.assertEqual(len(result), 0)

        # Make sure the extension process starts
        extension = self._run_extension(
            path=daemon.options["extensions_socket"],
            timeout=EXTENSION_TIMEOUT,
        )
        self.assertTrue(extension.isAlive())

        # Now that an extension has started, check extension list
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)
        ex_uuid = result.keys()[0]
        ex_data = result[ex_uuid]
        self.assertEqual(ex_data.name, "example")
        self.assertEqual(ex_data.version, "0.0.1")
        self.assertEqual(ex_data.min_sdk_version, "0.0.0")

        # Get a python-based thrift client to the extension's service
        client2 = test_base.EXClient(daemon.options["extensions_socket"],
                                     uuid=ex_uuid)
        self.assertTrue(client2.open(timeout=EXTENSION_TIMEOUT))
        ex = client2.getEX()
        self.assertEqual(ex.ping().code, 0)

        # Make sure the extension can receive a call
        em_time = em.call("table", "time", {"action": "columns"})
        ex_time = ex.call("table", "time", {"action": "columns"})
        print(em_time)
        print(ex_time)
        self.assertEqual(ex_time.status.code, 0)
        self.assertTrue(len(ex_time.response) > 0)
        self.assertTrue("name" in ex_time.response[0])
        self.assertEqual(ex_time.status.uuid, ex_uuid)

        # Make sure the extension includes a custom registry plugin
        result = ex.call("table", "example", {"action": "generate"})
        print(result)
        self.assertEqual(result.status.code, 0)
        self.assertEqual(len(result.response), 1)
        self.assertTrue("example_text" in result.response[0])
        self.assertTrue("example_integer" in result.response[0])
        self.assertEqual(result.response[0]["example_text"], "example")

        # Make sure the core can route to the extension
        result = em.call("table", "example", {"action": "generate"})
        print(result)

        client2.close()
        client.close()
        extension.kill()
        daemon.kill()

    def test_extension_dies(self):
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_interval": "0",
            "verbose": True,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # Make sure there are no extensions registered
        result = test_base.expect(em.extensions, 0)
        self.assertEqual(len(result), 0)

        # Make sure the extension process starts
        extension = self._run_extension(
            path=daemon.options["extensions_socket"],
            timeout=EXTENSION_TIMEOUT)
        self.assertTrue(extension.isAlive())

        # Now that an extension has started, check extension list
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        # Kill the extension
        extension.kill()

        # Make sure the daemon detects the change
        result = test_base.expect(em.extensions, 0, timeout=EXTENSION_TIMEOUT)
        self.assertEqual(len(result), 0)

        # Make sure the extension restarts
        extension = self._run_extension(
            path=daemon.options["extensions_socket"],
            timeout=EXTENSION_TIMEOUT,
        )
        self.assertTrue(extension.isAlive())

        # With the reset there should be 1 extension again
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)
        print(em.query("select * from example"))

        # Now tear down the daemon
        client.close()
        daemon.kill()

        # The extension should tear down as well
        self.assertTrue(extension.isDead(extension.pid))

    def test_extension_timeout(self):
        # Start an extension without a daemon, with a timeout.
        extension = self._run_extension(timeout=EXTENSION_TIMEOUT)
        self.assertTrue(extension.isAlive())

        # Now start a daemon
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_socket": extension.options["extensions_socket"],
            "verbose": True,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(extension.options["extensions_socket"])
        test_base.expectTrue(client.try_open)
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)
        extension.kill()

    def test_extensions_autoload(self):
        loader = test_base.Autoloader(
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_timeout": EXTENSION_TIMEOUT,
            "extensions_autoload": loader.path,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_extensions_directory_autoload(self):
        utils.copy_file(test_base.ARGS.build + "/osquery/example_extension.ext",
            test_base.CONFIG_DIR)
        loader = test_base.Autoloader([test_base.CONFIG_DIR])
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_timeout": EXTENSION_TIMEOUT,
            "extensions_autoload": loader.path,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_extensions_autoload_watchdog(self):
        loader = test_base.Autoloader(
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({
            "extensions_timeout": EXTENSION_TIMEOUT,
            "extensions_autoload": loader.path,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_external_config(self):
        loader = test_base.Autoloader(
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({
            "extensions_autoload": loader.path,
            "extensions_timeout": EXTENSION_TIMEOUT,
            "config_plugin": "example",
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        # If there are no extensions the daemon may have exited (in error).
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_external_config_update(self):
        # Start an extension without a daemon, with a timeout.
        extension = self._run_extension(timeout=EXTENSION_TIMEOUT)
        self.assertTrue(extension.isAlive())

        # Now start a daemon
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_timeout": EXTENSION_TIMEOUT,
            "extensions_socket": extension.options["extensions_socket"],
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client to the manager and extension.
        client = test_base.EXClient(extension.options["extensions_socket"])
        test_base.expectTrue(client.try_open)
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # Need the manager to request the extension's UUID.
        result = test_base.expect(em.extensions, 1)
        self.assertTrue(result is not None)
        ex_uuid = result.keys()[0]
        client2 = test_base.EXClient(extension.options["extensions_socket"],
            uuid=ex_uuid)
        test_base.expectTrue(client2.try_open)
        self.assertTrue(client2.open(timeout=EXTENSION_TIMEOUT))
        ex = client2.getEX()

        # Trigger an async update from the extension.
        request = {
            "action": "update",
            "source": "test",
            "data": "{\"options\": {\"config_plugin\": \"update_test\"}}"}
        ex.call("config", "example", request)

        # The update call in the extension should filter to the core.
        options = em.options()
        self.assertTrue("config_plugin" in options.keys())
        self.assertTrue(options["config_plugin"], "update_test")

        # Cleanup thrift connections and subprocesses.
        client2.close()
        client.close()
        extension.kill()
        daemon.kill()

    def test_extensions_settings(self):
        loader = test_base.Autoloader(
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_timeout": EXTENSION_TIMEOUT,
            "extensions_autoload": loader.path,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client for the manager (core).
        client = test_base.EXClient(daemon.options["extensions_socket"])
        self.assertTrue(client.open(timeout=EXTENSION_TIMEOUT))
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        # This expect statement will block with a short timeout.
        result = test_base.expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        # The 'complex_example' table reports several columns.
        # Each is a 'test_type', check each expected value.
        result = em.query("select * from complex_example")
        if len(result.response) == 0:
            # There is a brief race between register and registry broadcast
            # That fast external client fight when querying tables.
            # Other config/logger plugins have wrappers to retry/wait.
            time.sleep(0.5)
            result = em.query("select * from complex_example")

        self.assertEqual(result.response[0]['flag_test'], 'false')
        self.assertEqual(result.response[0]['database_test'], '1')

        client.close()
        daemon.kill(True)

if __name__ == "__main__":
    test_base.assertPermissions()
    module = test_base.Tester()

    # Find and import the thrift-generated python interface
    test_base.loadThriftFromBuild(test_base.ARGS.build)

    module.run()

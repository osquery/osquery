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

import glob
import os
import psutil
import signal
import subprocess
import sys
import time
import threading
import unittest

try:
    from thrift import Thrift
    from thrift.transport import TSocket
    from thrift.transport import TTransport
    from thrift.protocol import TBinaryProtocol
except ImportError:
    print ("Cannot import thrift: pip install thrift?")
    exit(1)

# osquery-specific testing utils
import test_base

class EXClient:
    transport = None

    def __init__(self, path=None, uuid=None):
        if path is None:
            path = test_base.CONFIG["options"]["extensions_socket"]
        self.path = path
        if uuid:
            self.path += ".%s" % str(uuid)
        transport = TSocket.TSocket(unix_socket=self.path)
        transport = TTransport.TBufferedTransport(transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self.transport = transport

    def close(self):
        if self.transport:
            self.transport.close()

    def open(self):
        '''Attempt to open the UNIX domain socket.'''
        try:
            self.transport.open()
        except Exception as e:
            return False
        return True

    def getEM(self):
        '''Return an extension manager (osquery core) client.'''
        return ExtensionManager.Client(self.protocol)

    def getEX(self):
        '''Return an extension (osquery extension) client.'''
        return Extension.Client(self.protocol)


def expect(functional, expected, interval=0.2, timeout=2):
    """Helper function to run a function with expected latency"""
    delay = 0
    result = None
    while result is None or len(result) != expected:
        try:
            result = functional()
            if len(result) == expected: break
        except: pass
        if delay >= timeout:
            return None
        time.sleep(interval)
        delay += interval
    return result


def expectTrue(functional, interval=0.2, timeout=2): 
    """Helper function to run a function with expected latency"""
    delay = 0
    while delay < timeout:
        if functional():
            return True
        time.sleep(interval)
        delay += interval
    return False


class ExtensionTests(test_base.ProcessGenerator, unittest.TestCase):
    def tearDown(self):
        stale_sockets = glob.glob("/tmp/osquery-test.em*")
        for stale_socket in stale_sockets:
            os.remove(stale_socket)
            os.system("killall osqueryd")

    def test_1_daemon_without_extensions(self):
        # Start the daemon without thrift, prefer no watchdog because the tests
        # kill the daemon very quickly.
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "disable_extensions": True,
        })
        self.assertTrue(daemon.isAlive())

        # Now try to connect to the disabled API
        client = EXClient()
        self.assertFalse(client.open())
        daemon.kill()

    def test_2_daemon_api(self):
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # List the number of extensions
        print (em.ping())
        result = expect(em.extensions, 0)
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

    def test_3_example_extension(self):
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())
        
        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # Make sure there are no extensions registered
        result = expect(em.extensions, 0)
        self.assertEqual(len(result), 0)

        # Make sure the extension process starts
        extension = self._run_extension()
        self.assertTrue(extension.isAlive())

        # Now that an extension has started, check extension list
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)
        ex_uuid = result.keys()[0]
        ex_data = result[ex_uuid]
        self.assertEqual(ex_data.name, "example")
        self.assertEqual(ex_data.version, "0.0.1")
        self.assertEqual(ex_data.min_sdk_version, "0.0.0")

        # Get a python-based thrift client to the extension's service
        client2 = EXClient(uuid=ex_uuid)
        client2.open()
        ex = client2.getEX()
        self.assertEqual(ex.ping().code, 0)

        # Make sure the extension can receive a call
        em_time = em.call("table", "time", {"action": "columns"})
        ex_time = ex.call("table", "time", {"action": "columns"})
        print (em_time)
        print (ex_time)
        self.assertEqual(ex_time.status.code, 0)
        self.assertTrue(len(ex_time.response) > 0)
        self.assertTrue("name" in ex_time.response[0])
        self.assertEqual(ex_time.status.uuid, ex_uuid)

        # Make sure the extension includes a custom registry plugin
        result = ex.call("table", "example", {"action": "generate"})
        print (result)
        self.assertEqual(result.status.code, 0)
        self.assertEqual(len(result.response), 1)
        self.assertTrue("example_text" in result.response[0])
        self.assertTrue("example_integer" in result.response[0])
        self.assertEqual(result.response[0]["example_text"], "example")

        # Make sure the core can route to the extension
        result = em.call("table", "example", {"action": "generate"})
        print (result)

        client2.close()
        client.close()
        extension.kill()
        daemon.kill()

    def test_4_extension_dies(self):
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())
        
        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # Make sure there are no extensions registered
        result = expect(em.extensions, 0)
        self.assertEqual(len(result), 0)

        # Make sure the extension process starts
        extension = self._run_extension()
        self.assertTrue(extension.isAlive())

        # Now that an extension has started, check extension list
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        # Kill the extension
        extension.kill()

        # Make sure the daemon detects the change
        result = expect(em.extensions, 0, timeout=5)
        self.assertEqual(len(result), 0)

        # Make sure the extension restarts
        extension = self._run_extension()
        self.assertTrue(extension.isAlive())

        # With the reset there should be 1 extension again
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)
        print (em.query("select * from example"))

        # Now tear down the daemon
        client.close()
        daemon.kill()

        # The extension should tear down as well
        self.assertTrue(extension.isDead(extension.pid))

    def test_5_extension_timeout(self):
        # Start an extension without a daemon, with a timeout.
        extension = self._run_extension(timeout=3)
        self.assertTrue(extension.isAlive())

        # Now start a daemon
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)
        extension.kill()

    def test_6_extensions_autoload(self):
        loader = test_base.Autoloader("/tmp/osqueryd-temp-ext.load",
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({
            "disable_watchdog": True,
            "extensions_autoload": loader.path,
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_7_extensions_autoload_watchdog(self):
        loader = test_base.Autoloader("/tmp/osqueryd-temp-ext.load",
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({"extensions_autoload": loader.path})
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_8_external_config(self):
        loader = test_base.Autoloader("/tmp/osqueryd-temp-ext.load",
            [test_base.ARGS.build + "/osquery/example_extension.ext"])
        daemon = self._run_daemon({
            "extensions_autoload": loader.path,
            "config_plugin": "example",
        })
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = EXClient()
        expectTrue(client.open)
        self.assertTrue(client.open())
        em = client.getEM()

        # The waiting extension should have connected to the daemon.
        # If there are no extensions the daemon may have exited (in error).
        result = expect(em.extensions, 1)
        self.assertEqual(len(result), 1)

        client.close()
        daemon.kill(True)

    def test_9_external_config_update(self):
        # Start an extension without a daemon, with a timeout.
        extension = self._run_extension(timeout=3)
        self.assertTrue(extension.isAlive())

        # Now start a daemon
        daemon = self._run_daemon({"disable_watchdog": True})
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client to the manager and extension.
        client = EXClient()
        client.open()
        em = client.getEM()
        # Need the manager to request the extension's UUID.
        result = expect(em.extensions, 1)
        self.assertTrue(result is not None)
        ex_uuid = result.keys()[0]
        client2 = EXClient(uuid=ex_uuid)
        client2.open()
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


if __name__ == "__main__":
    module = test_base.Tester()

    # Find and import the thrift-generated python interface
    thrift_path = test_base.ARGS.build + "/generated/gen-py"
    try:
        sys.path.append(thrift_path)
        from osquery import *
    except ImportError:
        print ("Cannot import osquery thrift API from %s" % (thrift_path))
        print ("You must first run: make")
        exit(1)

    module.run()

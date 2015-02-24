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
import psutil
import signal
import subprocess
import sys
import time
import threading
import unittest

try:
    import argparse
except ImportError:
    print ("Cannot import argparse: pip install argparse?")
    exit(1)

try:
    from thrift import Thrift
    from thrift.transport import TSocket
    from thrift.transport import TTransport
    from thrift.protocol import TBinaryProtocol
except ImportError:
    print ("Cannot import thrift: pip install thrift?")
    exit(1)

# Import the testing utils
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/tests/")
try:
    from utils import *
except ImportError:
    print ("Cannot import osquery testing utils from ./tools/tests")
    exit(1)

# For each daemon test, write a config
CONFIG_NAME = "/tmp/osquery-extensions-test"
DEFAULT_CONFIG = {
    "options": {
        "db_path": "%s.db" % CONFIG_NAME,
        "pidfile": "%s.pid" % CONFIG_NAME,
        "config_path": "%s.conf" % CONFIG_NAME,
        "extensions_socket": "%s.em" % CONFIG_NAME,
        "watchdog_level": "3",
        "disable_logging": "true",
        "force": "true",
    },
    "scheduledQueries": [],
}

# Defaults
PLATFORM = sys.platform if sys.platform != "linux2" else "linux"
CONFIG = DEFAULT_CONFIG
VERBOSE = False
BUILD = "./build/%s/" % (PLATFORM)

class ProcRunner(object):
    def __init__(self, name, path, _args=[], interval=0.2, silent=False):
        self.proc = None
        self.name = name
        self.path = path
        self.args = _args
        self.interval = interval
        self.silent = silent
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        try:
            if self.silent:
                self.proc = subprocess.Popen([self.path] + self.args,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                self.proc = subprocess.Popen([self.path] + self.args)
        except Exception as e:
            print (red("Process start failed:") + " %s" % self.name)
            print (str(e))
            sys.exit(1)
        try:
            while self.proc.poll() is None:
                time.sleep(self.interval)
            self.proc = None
        except:
            return
        print ("Process %s ended" % self.name)

    def getChildren(self, max_interval=1):
        if not self.proc:
            return []
        proc = psutil.Process(pid=self.proc.pid)
        delay = 0
        while len(proc.get_children()) == 0:
            if delay > max_interval:
                return []
            time.sleep(self.interval)
            delay += self.interval
        return proc.get_children()

    @property
    def pid(self):
        return self.proc.pid if self.proc is not None else None

    def kill(self):
        if self.proc:
            try:
                self.proc.kill()
            except:
                pass
        self.proc = None

    def isAlive(self, timeout=1):
        delay = 0
        while self.proc is None:
            if delay > timeout:
                break
            time.sleep(self.interval)
            delay += self.interval
        return self.proc.poll() is None

    def isDead(self, pid, timeout=5):
        proc = psutil.Process(pid=pid)
        delay = 0
        while delay < timeout:
            if not proc.is_running():
                return True
            time.sleep(delay)
            delay += self.interval
        return False

class EXClient:
    transport = None

    def __init__(self, path, uuid=None):
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
        try:
            self.transport.open()
        except:
            return False
        return True

    def getEM(self):
        return ExtensionManager.Client(self.protocol)

    def getEX(self):
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

class ProcessGenerator(object):
    generators = []

    def _run_daemon(self, config, silent=False):
        write_config(config)
        daemon = ProcRunner("daemon", os.path.join(BUILD, "osquery/osqueryd"),
            [
                "--config_path=%s.conf" % CONFIG_NAME,
                "--verbose" if VERBOSE else ""
            ],
            silent=silent)
        self.generators.append(daemon)
        return daemon

    def _run_extension(self, silent=False):
        extension = ProcRunner("extension",
            os.path.join(BUILD, "osquery/example_extension"),
            [
                "--extensions_socket=%s.em" % CONFIG_NAME,
                "--verbose" if VERBOSE else ""
            ],
            silent=silent)
        self.generators.append(extension)
        return extension

    def tearDown(self):
        for generator in self.generators:
            if generator.pid is not None:
                try:
                    os.kill(generator.pid, signal.SIGKILL)
                except:
                    pass

class WatchdogTests(ProcessGenerator, unittest.TestCase):
    @unittest.skipIf("--extensions" in sys.argv, "only running extensions")
    def setUp(self):
        pass

    def test_1_daemon_without_watchdog(self):
        config = CONFIG.copy()
        config["options"]["disable_watchdog"] = "true"
        config["options"]["disable_extensions"] = "true"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())
        daemon.kill()

    def test_2_daemon_with_watchdog(self):
        config = CONFIG.copy()
        config["options"]["disable_watchdog"] = "false"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())

        # Check that the daemon spawned a child process
        children = daemon.getChildren()
        self.assertTrue(len(children) > 0)
        daemon.kill()

        # This will take a few moments to make sure the client process
        # dies when the watcher goes away
        self.assertTrue(daemon.isDead(children[0].pid))

class ExtensionTests(ProcessGenerator, unittest.TestCase):
    def test_1_daemon_without_extensions(self):
        # Start the daemon without thrift, prefer no watchdog because the tests
        # kill the daemon very quickly.
        config = CONFIG.copy()
        config["options"]["disable_watchdog"] = "true"
        config["options"]["disable_extensions"] = "true"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())

        # Now try to connect to the disabled API
        client = EXClient(config["options"]["extensions_socket"])
        self.assertFalse(client.open())
        daemon.kill()

    def test_2_daemon_api(self):
        config = CONFIG.copy()
        config["options"]["disable_watchdog"] = "true"
        config["options"]["disable_extensions"] = "false"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())

        # Get a python-based thrift client
        client = EXClient(config["options"]["extensions_socket"])
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
        config = CONFIG.copy()
        config["options"]["disable_watchdog"] = "true"
        config["options"]["disable_extensions"] = "false"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())
        
        # Get a python-based thrift client
        client = EXClient(config["options"]["extensions_socket"])
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
        client2 = EXClient(config["options"]["extensions_socket"], ex_uuid)
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
        config = CONFIG.copy()
        config["options"]["disable_watchdog"] = "true"
        config["options"]["disable_extensions"] = "false"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())
        
        # Get a python-based thrift client
        client = EXClient(config["options"]["extensions_socket"])
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

        # Make sure the extension restart
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "Test the osquery extensions API."
    ))
    parser.add_argument(
        "--config", metavar="FILE", default=None,
        help="Use special options from a config."
    )
    parser.add_argument(
        "--extensions", default=False, action="store_true",
        help="Only run extensions tests."
    )
    parser.add_argument(
        "--verbose", default=False, action="store_true",
        help="Run daemons and extensions with --verbose"
    )

    # Directory structure options
    parser.add_argument(
        "--build", metavar="PATH", default=BUILD,
        help="Path to osquery build (./build/<sys>/)."
    )
    args = parser.parse_args()

    if not os.path.exists(args.build):
        print ("Cannot find --build: %s" % args.build)
        print ("You must first: make")
        exit(1)

    # Find and import the thrift-generated python interface
    thrift_path = args.build + "/generated/gen-py"
    try:
        sys.path.append(thrift_path)
        from osquery import *
    except ImportError:
        print ("Cannot import osquery from %s" % (thrift_path))
        print ("You must first: make python-thrift")
        exit(1)

    # Write config
    CONFIG = read_config(args.config) if args.config else DEFAULT_CONFIG
    VERBOSE = args.verbose
    BUILD = args.build

    os.setpgrp()
    unittest.main(argv=[sys.argv[0], "-v" if VERBOSE else ""])

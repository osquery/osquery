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
import psutil
import re
import subprocess
import signal
import sys
import time
import threading
import unittest

import pexpect
try:
    from pexpect.replwrap import REPLWrapper
except ImportError as e:
    print("Could not import pexpect.replwrap: %s" % (str(e)))
    print("  Need pexpect version 3.3, installed version: %s" % (
        str(pexpect.__version__)))
    print("  pexpect location: %s" % (str(pexpect.__file__)))
    exit(1)

try:
    import argparse
except ImportError:
    print ("Cannot import argparse: pip install argparse?")
    exit(1)

'''Defaults that should be used in integration tests.'''
CONFIG_NAME = "/tmp/osquery-test"
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

# osquery-specific python tooling and utilities
import utils

'''Expect CONFIG to be set during Tester.main() to a python dict.'''
CONFIG = None
'''Expect ARGS to contain the argparsed namespace.'''
ARGS = None

class OsqueryUnknownException(Exception):
    '''Exception thrown for unknown output from the shell'''
    pass


class OsqueryException(Exception):
    '''Exception thrown when the shell returns an error'''
    pass


class OsqueryWrapper(REPLWrapper):
    '''A pexpect wrapper intended for interacting with the osqueryi REPL'''
    PROMPT = u'osquery> '
    CONTINUATION_PROMPT = u'    ...> '
    ERROR_PREFIX = 'Error:'

    def __init__(self, command='../osqueryi', args=None):
        if args:
            command = command + " " + " ".join(["--%s=%s" % (k, v) for
                k, v in args.iteritems()])
        super(OsqueryWrapper, self).__init__(
            command,
            self.PROMPT,
            None,
            continuation_prompt=self.CONTINUATION_PROMPT)

    def run_query(self, query):
        '''Run a query, returning the results as a list of dictionaries

        When unknown output is encountered, OsqueryUnknownException is thrown.
        When osqueryi returns an error, OsqueryException is thrown.
        '''
        query = query + ';'  # Extra semicolon causes no harm
        result = self.run_command(query)
        # On Mac, the query appears first in the string. Remove it if so.
        result = re.sub(re.escape(query), '', result).strip()
        result_lines = result.splitlines()

        if len(result_lines) < 1:
            raise OsqueryUnknownException(
                'Unexpected output:\n %s' % result_lines)
        if result_lines[0].startswith(self.ERROR_PREFIX):
            raise OsqueryException(result_lines[0])

        try:
            header = result_lines[1]
            columns = re.findall('[^ |]+', header)
            rows = []
            for line in result_lines[3:-1]:
                values = re.findall('[^ |]+', line)
                rows.append(
                    dict((col, val) for col, val in zip(columns, values)))
            return rows
        except:
            raise OsqueryUnknownException(
                'Unexpected output:\n %s' % result_lines)


class ProcRunner(object):
    '''A helper class to open a subprocess and perform testing actions.

    The subprocess is opened in a new thread and state is tracked using
    this class wrapper.
    '''
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
            print (utils.red("Process start failed:") + " %s" % self.name)
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
        '''Get the child pids.'''
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
        '''Check if the process is alive.'''
        delay = 0
        while self.proc is None:
            if delay > timeout:
                break
            time.sleep(self.interval)
            delay += self.interval
        if self.proc is None:
            return False
        return self.proc.poll() is None

    def isDead(self, pid, timeout=5):
        '''Check if the process was killed.

        This is different than `isAlive` in that the timeout is an expectation
        that the process will die before the timeout, `isAlive`'s timeout is
        an expectation that the process will be scheduled before the timeout.
        '''
        try:
            proc = psutil.Process(pid=pid)
        except psutil.NoSuchProcess as e:
            return True
        delay = 0
        while delay < timeout:
            if not proc.is_running():
                return True
            time.sleep(self.interval)
            delay += self.interval
        return False


class ProcessGenerator(object):
    '''Helper methods to patch into a unittest'''
    generators = []

    def _run_daemon(self, config, silent=False):
        '''Spawn an osquery daemon process'''
        global ARGS, CONFIG_NAME
        utils.write_config(config)
        binary = os.path.join(ARGS.build, "osquery", "osqueryd")
        config = ["--%s=%s" % (k, v) for k, v in config["options"].items()]
        daemon = ProcRunner("daemon", binary,
            [
                "--config_path=%s.conf" % CONFIG_NAME,
                "--verbose" if ARGS.verbose else ""
            ] + config,
            silent=silent)
        self.generators.append(daemon)
        return daemon

    def _run_extension(self, silent=False):
        '''Spawn an osquery extension (example_extension)'''
        global ARGS, CONFIG_NAME
        binary = os.path.join(ARGS.build, "osquery",
            "example_extension")
        extension = ProcRunner("extension",
            binary,
            [
                "--socket=%s" % CONFIG["options"]["extensions_socket"],
                "--verbose" if ARGS.verbose else ""
            ],
            silent=silent)
        self.generators.append(extension)
        return extension

    def tearDown(self):
        '''When the unittest stops, clean up child-generated processes.

        Iterate through the generated daemons and extensions, and kill -9 them.
        Unittest should stop processes they generate, but on failure the
        tearDown method will cleanup.
        '''
        for generator in self.generators:
            if generator.pid is not None:
                try:
                    os.kill(generator.pid, signal.SIGKILL)
                except Exception as e:
                    pass


class Tester(object):
    def __init__(self):
        global ARGS, CONFIG
        parser = argparse.ArgumentParser(description=(
            "osquery python integration testing."
        ))
        parser.add_argument(
            "--config", metavar="FILE", default=None,
            help="Use special options from a config."
        )
        parser.add_argument(
            "--verbose", default=False, action="store_true",
            help="Run daemons and extensions with --verbose"
        )

        # Directory structure options
        parser.add_argument(
            "--build", metavar="PATH", default=".",
            help="Path to osquery build (./build/<sys>/)."
        )
        ARGS = parser.parse_args()

        if not os.path.exists(ARGS.build):
            print ("Cannot find --build: %s" % ARGS.build)
            print ("You must first run: make")
            exit(1)

        # Write config
        CONFIG = read_config(ARGS.config) if ARGS.config else DEFAULT_CONFIG

    def run(self):
        os.setpgrp()

        unittest_args = [sys.argv[0]]
        if ARGS.verbose:
            unittest_args += ["-v"]
        unittest.main(argv=unittest_args)

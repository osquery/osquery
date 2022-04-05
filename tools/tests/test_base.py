#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import copy
import getpass
import os
import psutil
import random
import re
import signal
import subprocess
import sys
import tempfile
import time
import threading
import unittest
import utils


# TODO: Find an implementation that will work for Windows, for now, disable.
# https://goo.gl/T4AgV5
if os.name == "nt":
    # We redefine timeout_decorator on windows
    class timeout_decorator:
        @staticmethod
        def timeout(*args, **kwargs):
            # return a no-op decorator
            return lambda f: f
else:
    import timeout_decorator


def patched_run_command(self, command, timeout=-1, async_=False):
    '''A patched 'run_command' from the pexpect module.

    The original module and method do not support a bytes object in the final
    string-join concatenation. We copy-paste most of the method and add a
    decode and encode to preserve the function logic (make it look as similar
    to the original as possible).

    See https://pexpect.readthedocs.io/en/stable/_modules/pexpect/replwrap.html
    '''
    # Split up multiline commands and feed them in bit-by-bit
    cmdlines = command.splitlines()
    # splitlines ignores trailing newlines - add it back in manually
    if command.endswith('\n'):
        cmdlines.append('')
    if not cmdlines:
        raise ValueError("No command was given")

    if async_:
        from ._async import repl_run_command_async
        return repl_run_command_async(self, cmdlines, timeout)

    res = []
    self.child.sendline(cmdlines[0])
    for line in cmdlines[1:]:
        self._expect_prompt(timeout=timeout)
        res.append(self.child.before.decode("utf-8"))
        self.child.sendline(line)

    # Command was fully submitted, now wait for the next prompt
    if self._expect_prompt(timeout=timeout) == 1:
        # We got the continuation prompt - command was incomplete
        self.child.kill(signal.SIGINT)
        self._expect_prompt(timeout=1)
        raise ValueError("Continuation prompt found - input was incomplete:\n"
                            + command)
    res = "".join(res + [self.child.before.decode("utf-8")])
    return res.encode()


# We use a generic 'expect' style subprocess manager on Windows
if os.name == "nt":
    from winexpect import REPLWrapper, WinExpectSpawn
else:
    import pexpect
    try:
        from pexpect.replwrap import REPLWrapper
    except ImportError as e:
        print("Could not import pexpect.replwrap: %s" % (str(e)))
        print("  Need pexpect version 3.3, installed version: %s" %
              (str(pexpect.__version__)))
        print("  pexpect location: %s" % (str(pexpect.__file__)))
        exit(1)

    '''Patch the existing run command'''
    REPLWrapper.run_command = patched_run_command


try:
    import argparse
except ImportError:
    print("Cannot import argparse: pip install argparse?")
    exit(1)

try:
    from thrift import Thrift
    from thrift.transport import TSocket
    from thrift.transport import TTransport
    from thrift.protocol import TBinaryProtocol
except ImportError as e:
    print("Cannot import thrift: pip install thrift?")
    print(str(e))
    exit(1)


def getUserId():
    if os.name == "nt":
        return getpass.getuser()
    return "%d" % os.getuid()


'''Defaults that should be used in integration tests.'''
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TEMP_DIR = os.path.join(tempfile.gettempdir(),
                          "osquery-tests-python-%s" % (getUserId()))
TEMP_NAME = os.path.join(TEMP_DIR, "tests")
DEFAULT_CONFIG = {
    "options": {
        "flagfile": "/dev/null" if os.name == "posix" else "",
        "config_path": "/dev/null" if os.name == "posix" else "",
        "pidfile": "%s.pid" % TEMP_NAME,
        "extensions_autoload": "/dev/null" if os.name == "posix" else "",
        "extensions_socket": "/dev/null" if os.name == "posix" else "",
        "disable_database": "true",
        "disable_extensions": "true",
        "disable_logging": "true",
        "disable_events": "true",
        "force": "true",
        "watchdog_level": "3",
    },
    "schedule": {}
}

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
    ERROR_PREFIX = u'Error:'

    def __init__(self, command='../osqueryi', args={}, env=None):
        global CONFIG
        options = copy.deepcopy(CONFIG)["options"]
        for option in args.keys():
            options[option] = args[option]
        command = command + " " + " ".join(
            ["--%s=%s" % (k, v) for k, v in options.items()])
        if os.name == "nt":
            proc = WinExpectSpawn(command, env=env, cwd=TEST_CONFIGS_DIR)
        else:
            proc = pexpect.spawn(command, env=env, cwd=TEST_CONFIGS_DIR)

        super().__init__(
            proc,
            self.PROMPT,
            None,
            continuation_prompt=self.CONTINUATION_PROMPT)

    def run_query(self, query):
        '''Run a query, returning the results as a list of dictionaries

        When unknown output is encountered, OsqueryUnknownException is thrown.
        When osqueryi returns an error, OsqueryException is thrown.
        '''
        query = query + ';'  # Extra semicolon causes no harm
        result = self.run_command(query).decode('utf-8')
        # On Mac, the query appears first in the string. Remove it if so.
        result = re.sub(re.escape(query), '', result).strip()
        result_lines = result.splitlines()
        if len(result_lines) < 2:
            raise OsqueryUnknownException(
                'Unexpected output:\n %s' % result_lines[0])
        if result_lines[1].startswith(self.ERROR_PREFIX):
            raise OsqueryException(result_lines[1])

        noise = 0
        for l in result_lines:
            if len(l) == 0 or l[0] != '+':
                # This is not a result line
                noise += 1
            elif l[0] == '+':
                break
        for l in range(noise):
            result_lines.pop(0)

        try:
            header = result_lines[1]
            columns = re.findall('[^ |]+', header)
            rows = []
            for line in result_lines[3:-1]:
                if len(line) > 0 and line[0] == '+':
                    continue
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

    def __init__(self, name, path, _args=[], interval=1, silent=False):
        self.started = False
        self.proc = None
        self.name = name
        self.path = path
        self.args = _args
        self.interval = interval
        self.silent = silent
        self.retcode = -1
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        try:
            if self.silent:
                self.proc = subprocess.Popen(
                    [self.path] + self.args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            else:
                self.proc = subprocess.Popen([self.path] + self.args)
            self.started = True
        except Exception as e:
            print(utils.red("Process start failed:") + " %s" % self.name)
            print(str(e))
            sys.exit(1)
        try:
            while self.proc.poll() is None:
                self.started = True
                time.sleep(0.1)
            self.started = True
            self.retcode = -1 if self.proc is None else self.proc.poll()
        except Exception as e:
            return

    def requireStarted(self, attempts=5):
        for _ in range(attempts):
            if self.started is True:
                break
            time.sleep(self.interval)

    def getChildren(self, attempts=5):
        '''Get the child pids.'''
        self.requireStarted()
        if not self.proc:
            return []
        try:
            proc = psutil.Process(pid=self.proc.pid)
            attempt = 0
            while len(proc.children()) == 0:
                if attempt > attempts:
                    return []
                attempt += 1
                time.sleep(self.interval)
            return [p.pid for p in proc.children()]
        except:
            pass
        return []

    @property
    def code(self):
        self.requireStarted()
        return self.retcode

    @property
    def pid(self):
        self.requireStarted()
        return self.proc.pid if self.proc is not None else None

    def kill(self, children=False):
        self.requireStarted()
        sig = signal.SIGINT if os.name == "nt" else signal.SIGKILL
        if children:
            for child in self.getChildren():
                try:
                    os.kill(child, sig)
                except:
                    pass
        if self.proc:
            try:
                os.kill(self.pid, sig)
                self.proc.wait()   # == -sig.value on posix
            except:
                pass
        self.proc = None

    def isAlive(self, attempts=10):
        self.requireStarted()
        '''Check if the process is alive.'''
        attempt = 0
        while self.proc is None:
            if attempt > attempts:
                break
            time.sleep(self.interval)
            attempt += 1
        if self.proc is None:
            return False
        return self.proc.poll() is None

    def isDead(self, pid, attempts=10):
        self.requireStarted()
        '''Check if the process was killed.

        This is different than `isAlive` in that the timeout is an expectation
        that the process will die before the timeout, `isAlive`'s timeout is
        an expectation that the process will be scheduled before the timeout.
        '''
        try:
            proc = psutil.Process(pid=pid)
        except psutil.NoSuchProcess as _:
            return True
        for _ in range(attempts):
            if not proc.is_running():
                return True
            time.sleep(self.interval)

        return False


def getLatestOsqueryBinary(binary):

    if os.name == "nt":
        normal_release_path = os.path.abspath(os.path.join(BUILD_DIR, "osquery", "{}.exe".format(binary)))

        if os.path.exists(normal_release_path):
            return normal_release_path

        msbuild_release_path = os.path.abspath(
        os.path.join(BUILD_DIR, "osquery", "Release", "{}.exe".format(binary)))
        msbuild_relwithdebinfo_path = os.path.abspath(
            os.path.join(BUILD_DIR, "osquery", "RelWithDebInfo", "{}.exe".format(binary)))

        if os.path.exists(msbuild_release_path) and os.path.exists(msbuild_relwithdebinfo_path):
            if os.stat(msbuild_release_path).st_mtime > os.stat(
                    msbuild_relwithdebinfo_path).st_mtime:
                return msbuild_release_path
            else:
                return msbuild_relwithdebinfo_path
        elif os.path.exists(msbuild_release_path):
            return msbuild_release_path
        elif os.path.exists(msbuild_relwithdebinfo_path):
            return msbuild_relwithdebinfo_path
    else:
        normal_release_path = os.path.abspath(os.path.join(BUILD_DIR, "osquery", binary))
        if os.path.exists(normal_release_path):
            return normal_release_path

    return None


class ProcessGenerator(object):
    '''Helper methods to patch into a unittest'''

    def setUp(self):
        self.generators = []
        utils.reset_dir(TEMP_DIR)

    def _run_daemon(self,
                    options={},
                    silent=False,
                    options_only={},
                    overwrite={}):
        '''Spawn an osquery daemon process'''
        global ARGS, TEMP_DIR, CONFIG
        config = copy.deepcopy(CONFIG)
        if len(options_only.keys()) > 0:
            # Create a temporary config.
            config["options"]["config_path"] = os.path.join(
                TEMP_DIR, "config-%d.json" % (random.randint(1000, 9999)))
        for option in options.keys():
            config["options"][option] = options[option]
        flags = ["--%s=%s" % (k, v) for k, v in config["options"].items()]
        for option in options_only.keys():
            config["options"][option] = options_only[option]
        for key in overwrite:
            config[key] = overwrite[key]
        if len(options_only.keys()) > 0:
            # Write the temporary config.
            utils.write_config(config)
        binary = getLatestOsqueryBinary('osqueryd')

        daemon = ProcRunner("daemon", binary, flags, silent=silent)
        daemon.options = config["options"]
        self.generators.append(daemon)
        return daemon

    def _run_extension(self, timeout=0, path=None, silent=False):
        '''Spawn an osquery extension (example_extension)'''
        global CONFIG, BUILD_DIR
        config = copy.deepcopy(CONFIG)
        binary = os.path.join(BUILD_DIR, "osquery", "examples", "example_extension.ext")
        if path is not None:
            config["options"]["extensions_socket"] = path
        extension = ProcRunner(
            "extension",
            binary, [
                "--socket=%s" % config["options"]["extensions_socket"],
                "--verbose" if not silent else "",
                "--timeout=%d" % timeout,
                "--interval=%d" % 0,
            ],
            silent=silent)
        self.generators.append(extension)
        extension.options = config["options"]
        return extension

    def tearDown(self):
        '''When the unit test stops, clean up child-generated processes.

        Iterate through the generated daemons and extensions, and kill -9 them.
        Unittest should stop processes they generate, but on failure the
        tearDown method will cleanup.
        '''
        sig = signal.SIGINT if os.name == "nt" else signal.SIGKILL
        for generator in self.generators:
            if generator.pid is not None:
                try:
                    os.kill(generator.pid, sig)
                except Exception as e:
                    pass
        self.generators = []


class EXClient(object):
    '''An osquery Thrift/extensions python client generator.'''
    transport = None
    '''The instance transport object.'''
    _manager = None
    '''The client class's reference to run-time discovered manager.'''
    _client = None
    '''The client class's reference to run-time discovered client.'''

    def __init__(self, path=None, uuid=None):
        global CONFIG
        '''Create a extensions client to a UNIX path and optional UUID.'''
        if path is None:
            path = CONFIG["options"]["extensions_socket"]
        self.path = path
        if uuid:
            self.path += ".%s" % str(uuid)
        transport = TSocket.TSocket(unix_socket=self.path)
        transport = TTransport.TBufferedTransport(transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self.transport = transport

    @classmethod
    def setUp(cls, manager, client):
        '''Set the manager and client modules to generate clients from.'''
        cls._manager = manager
        cls._client = client

    def close(self):
        if self.transport:
            self.transport.close()

    def try_open(self, attempts=10, interval=0.5):
        '''Try to open, on success, close the UNIX domain socket.'''
        did_open = self.open(attempts, interval)
        if did_open:
            self.close()
        return did_open

    def open(self, attempts=10, interval=0.5):
        '''Attempt to open the UNIX domain socket.'''
        delay = 0
        for i in range(0, attempts):
            try:
                self.transport.open()
                return True
            except Exception as e:
                pass

            time.sleep(interval)
        return False

    def getEM(self):
        '''Return an extension manager (osquery core) client.'''
        if self._manager is None:
            raise (Exception, "The EXClient must be 'setUp' with a manager")
        return self._manager.Client(self.protocol)

    def getEX(self):
        '''Return an extension (osquery extension) client.'''
        if self._client is None:
            raise (Exception, "The EXClient must be 'setUp' with a client")
        return self._client.Client(self.protocol)


class Autoloader(object):
    '''Helper class to write a module or extension autoload file.'''

    def __init__(self, autoloads=[]):
        global TEMP_DIR
        self.path = os.path.join(TEMP_DIR,
                                 "ext.load" + str(random.randint(1000, 9999)))
        with open(self.path, "w") as fh:
            fh.write("\n".join(autoloads))

    def __del__(self):
        try:
            os.unlink(self.path)
        except:
            pass


class TimeoutRunner(object):
    def __init__(self, cmd=[], timeout_sec=1):
        global CONFIG
        options = copy.deepcopy(CONFIG)["options"]
        args = ["--%s=%s" % (k, v) for k, v in options.items()]
        cmd = [cmd[0]] + args + cmd[1:]

        self.stdout = None
        self.stderr = None
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        kill_proc = lambda p: p.kill()
        timer = threading.Timer(timeout_sec, kill_proc, [self.proc])
        timer.start()
        self.stdout, self.stderr = self.proc.communicate()
        timer.cancel()


class SequentialTestLoader(unittest.TestLoader):
    def getTestCaseNames(self, testCaseClass):
        test_names = super().getTestCaseNames(testCaseClass)
        testcase_methods = list(testCaseClass.__dict__.keys())
        test_names.sort(key=testcase_methods.index)
        return test_names


class Tester(object):
    def __init__(self):
        global ARGS, CONFIG, TEMP_DIR, TEST_CONFIGS_DIR, BUILD_DIR
        parser = argparse.ArgumentParser(
            description=("osquery python integration testing."))

        parser.add_argument(
            "--test-configs-dir",
            required=True,
            help="Directory where the config files the test may use are"
        )

        parser.add_argument(
            "--config",
            metavar="FILE",
            default=None,
            help="Use special options from a config.")

        parser.add_argument(
            "--verbose",
            default=False,
            action="store_true",
            help="Run daemons and extensions with --verbose")

        # Directory structure options
        parser.add_argument(
            "--build",
            metavar="PATH",
            default=".",
            help="Path to osquery build (./build/<sys>/).")
        ARGS = parser.parse_args()

        if not os.path.exists(ARGS.build):
            print("Cannot find --build: %s" % ARGS.build)
            print("You must first run: make")
            exit(1)

        # Write config
        random.seed(time.time())

        utils.reset_dir(TEMP_DIR)
        CONFIG = read_config(ARGS.config) if ARGS.config else DEFAULT_CONFIG
        TEST_CONFIGS_DIR = ARGS.test_configs_dir
        BUILD_DIR = ARGS.build

    @timeout_decorator.timeout(20 * 60)
    def run(self):
        if os.name == "posix":
            os.setpgrp()
        unittest_args = [sys.argv[0]]
        if ARGS.verbose:
            unittest_args += ["-v"]
        unittest.main(argv=unittest_args, testLoader=SequentialTestLoader())


def expect(functional, expected, interval=0.01, timeout=4):
    """Helper function to run a function with expected latency"""
    delay = 0
    result = None
    while result is None or len(result) != expected:
        try:
            result = functional()
            if len(result) == expected:
                break
        except Exception as e:
            print("Expect exception (%s): %s not %s" %
                  (str(e), str(functional), expected))
            return None
        if delay >= timeout:
            return None
        time.sleep(interval)
        delay += interval
    return result


class QueryTester(ProcessGenerator, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.binary = getLatestOsqueryBinary("osqueryi")
        self.daemon = self._run_daemon({
            # The set of queries will hammer the daemon process.
            "disable_watchdog": True,
            # Enable the 'hidden' flag "registry_exceptions" to prevent
            # catching.
            "registry_exceptions": True,
            "ephemeral": True,
            "disable_extensions": False,
        })
        self.assertTrue(self.daemon.isAlive())

        # The sets of example tests will use the extensions APIs.
        self.client = EXClient(self.daemon.options["extensions_socket"])
        expectTrue(self.client.try_open, attempts=2, interval=5)
        self.assertTrue(self.client.open())
        self.em = self.client.getEM()

    def tearDown(self):
        self.client.close()
        self.daemon.kill()

    def _execute(self, query):
        try:
            result = self.em.query(query)
            self.assertEqual(result.status.code, 0)
            return result.response
        except Exception as e:
            print("General exception executing query: %s (%s)" %
                  (utils.lightred(query), str(e)))
            raise e

    def _execute_set(self, queries):
        for example in queries:
            start_time = time.time()
            print("Query: %s ..." % (example), end='')
            sys.stdout.flush()

            result = self._execute(example)
            end_time = time.time()
            duration_ms = int((end_time - start_time) * 1000)
            if duration_ms > 2000:
                # Query took longer than 2 seconds.
                duration_ms = utils.lightred(duration_ms)
            print(" (%sms) rows: %d" % (duration_ms, len(result)))


class CleanChildProcesses:
    # SO: 320232/ensuring-subprocesses-are-dead-on-exiting-python-program
    def __enter__(self):
        if os.name != "nt":
            os.setpgrp()
    def __exit__(self, type, value, traceback):
        try:
            if os.name != "nt":
                os.killpg(0, signal.SIGINT)
        except KeyboardInterrupt:
            # SIGINT is delivered to this process and children.
            pass


def expectTrue(functional, interval=1, attempts=10):
    """Helper function to run a function with expected latency"""
    for _ in range(0, attempts):
        if functional():
            return True
        time.sleep(interval)
    return False


def assertPermissions():
    stat_info = os.stat('.')
    if stat_info.st_uid != os.getuid():
        print(utils.lightred("Will not load modules/extensions in tests."))
        print(utils.lightred("Repository owner (%d) executer (%d) mismatch" % (
            stat_info.st_uid, os.getuid())))
        exit(1)


def getTestDirectory(base):
    path = os.path.join(base, "test-dir" + str(random.randint(1000, 9999)))
    utils.reset_dir(path)
    return path


def loadThriftFromBuild(build_dir):
    '''Import the thrift-generated python interface.'''
    try:
        from osquery.extensions import ExtensionManager, Extension
        EXClient.setUp(ExtensionManager, Extension)
    except ImportError as e:
        print("Cannot import osquery thrift API")
        print("Exception: %s" % (str(e)))
        exit(1)

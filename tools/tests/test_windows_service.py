#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import re
import os
import psutil
import random
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import unittest

from signal import SIGTERM

# osquery-specific testing utils
import test_base
import test_http_server

# Whether or not to use the watchdog process. leave this as false.
DISABLE_WATCHDOG = 'false'

# Global variable for powershell binary
POWERSHELL_ARGS = ['powershell.exe', '-noprofile']

TLS_SERVER_ARGS = {
    'tls': True,
    'persist': True,
    'timeout': test_http_server.HTTP_SERVER_TIMEOUT,
    'verbose': test_http_server.HTTP_SERVER_VERBOSE,
    'cert': test_http_server.HTTP_SERVER_CERT,
    'key': test_http_server.HTTP_SERVER_KEY,
    'ca': test_http_server.HTTP_SERVER_CA,
    'use_enroll_secret': test_http_server.HTTP_SERVER_USE_ENROLL_SECRET,
    'enroll_secret': test_http_server.HTTP_SERVER_ENROLL_SECRET
}

CONFIG_FILE = """
{
  "options": {

  },

  "schedule": {
    "processes_test": {
      "query": "select pid, name, path, cmdline from processes",
      "interval": 180
    }
  }
}
"""

FLAGS_FILE = """
--allow_unsafe=true
--config_plugin=tls
--config_tls_endpoint=/config
--config_tls_refresh=180
--enable_mouse_events
--enroll_secret_path={3}
--enroll_tls_endpoint=/enroll
--tls_hostname=localhost
--tls_server_certs={2}
--distributed_plugin=tls
--distributed_tls_read_endpoint=/distributed_read
--distributed_tls_write_endpoint=/distributed_write
--disable_extensions=true
--logger_plugin=tls,filesystem
--logger_path={0}
--logger_tls_compress
--logger_tls_endpoint=/log
--logger_tls_period=300
--logger_tls_max=4194304
--pidfile={1}
--database_disabled=true
--disable_events=false
--events_expiry=300
"""


def assertUserIsAdmin():
    if os.name != 'nt':
        sys.exit(-1)
    try:
        os.listdir('\\Windows\\Temp')
    except WindowsError:
        sys.exit(-1)


# Helper function for interacting with Windows SCM, -1 indicates an error
# with our helper function, other wise error code is the SCM reported issue
def sc(*args):
    p = None
    try:
        p = subprocess.Popen(
            ['sc.exe'] + list(args),
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
    except subprocess.CalledProcessError, err:
        return (err.returncode, err.output)

    out, _ = p.communicate()
    out = [x.strip() for x in out.split('\r\n') if x.strip() is not '']

    if len(out) >= 1:
        if 'SUCCESS' in out[0]:
            return (0, 'SUCCESS')
        if 'FAILED' in out[0]:
            err_code = re.findall(r'\d+', out[0])
            return (-1 if len(err_code) == 0 else int(err_code[0]), out[-1])

    for l in out:
        items = l.replace(' ', '').split(':')
        if len(items) > 1 and items[0] == 'STATE':
            return (0, items[1])

    # Generic catch all for SCM communications failure
    return (-1, 'UNKNOWN')


def findOsquerydBinary():
    script_root = os.path.split(os.path.abspath(__file__))[0]
    build_root = os.path.abspath(
        os.path.join(script_root, '..', '..', 'build', 'windows10', 'osquery'))
    path = os.path.join(build_root, 'Release', 'osqueryd.exe')
    if os.path.exists(path):
        return path
    path = os.path.join(build_root, 'RelWithDebInfo', 'osqueryd.exe')
    if os.path.exists(path):
        return path
    sys.exit(-1)


def installService(name, path):
    return sc('create', name, 'binPath=', path)


def uninstallService(name):
    return sc('delete', name)


def queryService(name):
    args = ['query', name]
    return sc(*args)


def getOsqueryProcs():
    return [
        p.pid for p in psutil.process_iter() if p.name() == 'osqueryd.exe'
    ]


def serviceAlive():
    return len(getOsqueryProcs()) == 2


def serviceDead():
    return len(getOsqueryProcs()) == 0


def serviceStopped(service_name):
    _, message = queryService(service_name)
    return message == '1STOPPED'


def serviceStarted(service_name):
    _, message = queryService(service_name)
    return message == '4RUNNING'


def startService(name, *argv):
    start_ = sc('start', name, *argv)
    test_base.expectTrue(serviceAlive)
    return start_[0]


def stopService(name):
    stop_ = sc('stop', name)
    test_base.expectTrue(serviceDead)
    return stop_[0]


def restartService(name, *argv):
    stop = stopService(name)
    start = startService(name, *argv)
    return start == 0 & stop == 0


def killOsqueryProcesses():
    if serviceAlive():
        procs = getOsqueryProcs()
        for p in procs:
            os.kill(p, SIGTERM)

# Before running this test, we should ensure that no residual
# processes exist on the system. We do so by getting any service
# that matches our regex, stopping it, and then deleting the service
def cleanOsqueryServices():
    service_args = POWERSHELL_ARGS + ['$(Get-Service osqueryd_test_*).Name']
    services = subprocess.check_output(service_args).split()

    # No services found on the system
    if len(services) == 0:
        return

    for service in services:
        stopService(service)
        # Local workaround as we need the service name
        def isServiceStopped():
            return serviceStopped(service)
        test_base.expectTrue(isServiceStopped)
        uninstallService(service)


class OsquerydTest(unittest.TestCase):

    service_list_ = []

    def setUp(self):
        # Ensure that no residual processes are alive before starting
        cleanOsqueryServices()

        self.test_instance = random.randint(0, 65535)
        self.tmp_dir = os.path.join(tempfile.gettempdir(),
                                    'osquery-test-python-{}'.format(
                                        self.test_instance))
        self.bin_path = findOsquerydBinary()

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

        os.mkdir(self.tmp_dir)

        self.pidfile = os.path.join(self.tmp_dir, 'osquery.pidfile')
        self.log_path = os.path.join(self.tmp_dir, 'log')
        self.database_path = os.path.join(self.tmp_dir, 'osquery.{}.db'.format(
            self.test_instance))
        self.config_path = os.path.join(self.tmp_dir, 'osquery.conf')
        self.flagfile = os.path.join(self.tmp_dir, 'osquery.flags')

        # Write out our mock configuration files
        with open(self.config_path, 'wb') as fd:
            fd.write(CONFIG_FILE)

        with open(self.flagfile, 'wb') as fd:
            fd.write(
                FLAGS_FILE.format(self.log_path, self.pidfile,
                                  test_http_server.HTTP_SERVER_CA,
                                  test_http_server.HTTP_SERVER_ENROLL_SECRET))

        # Start the test TLS server to add more internal services
        self.http_server_ = threading.Thread(
            target=test_http_server.run_http_server,
            args=(443, ),
            kwargs=TLS_SERVER_ARGS)
        self.http_server_.daemon = True
        self.http_server_.start()

    def runDaemon(self, *args):
        try:
            p = subprocess.Popen(
                [self.bin_path] + list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            start = time.time()
            while p.poll() is None:
                if time.time() - start > 5:
                    p.kill()
                    break
                time.sleep(1)

            return (p.stdout.read(), p.stderr.read())
        except subprocess.CalledProcessError:
            return ('', '')

    def test_install_run_stop_uninstall_windows_service(self):
        name = 'osqueryd_test_{}'.format(self.test_instance)
        code, _ = installService(name, self.bin_path)
        self.assertEqual(code, 0)
        self.service_list_.append(name)

        code = startService(name, '--flagfile', self.flagfile)
        self.assertEqual(code, 0)

        # Ensure the service is online before proceeding
        test_base.expectTrue(serviceAlive)

        _, output = queryService(name)
        self.assertEqual(output, '4RUNNING')

        # The daemon should not be able to load if the service is running
        _, stderr = self.runDaemon(
            '--allow_unsafe', '--verbose', '--config_path', self.config_path,
            '--database_path', self.database_path, '--logger_path',
            self.log_path, '--pidfile', self.pidfile)

        self.assertNotEqual(stderr.find('is already running'), -1)

        if code == 0:
            code = stopService(name)
            self.assertEqual(code, 0)

        test_base.expectTrue(serviceDead)
        self.assertTrue(serviceDead())

        _, output = queryService(name)
        self.assertEqual(output, '1STOPPED')
        code, _ = uninstallService(name)
        self.assertEqual(code, 0)

        self.service_list_.remove(name)

        # Make sure the service no longer exists, error code 1060
        code, _ = queryService(name)
        self.assertEqual(code, 1060)

    def test_thrash_windows_service(self):
        # Install the service
        name = 'osqueryd_test_{}'.format(self.test_instance)
        code, _ = installService(name, self.bin_path)
        self.assertEqual(code, 0)
        self.service_list_.append(name)

        code = startService(name, '--flagfile', self.flagfile)
        self.assertEqual(code, 0)

        test_base.expectTrue(serviceAlive)
        self.assertTrue(serviceAlive())

        for _ in range(5):
            status = restartService(name, '--flagfile', self.flagfile)
            self.assertTrue(status)
            test_base.expectTrue(serviceAlive)
            self.assertTrue(serviceAlive())

        code = stopService(name)
        self.assertEqual(code, 0)
        test_base.expectTrue(serviceDead)
        self.assertTrue(serviceDead())

        _, output = queryService(name)
        self.assertEqual(output, '1STOPPED')
        code, _ = uninstallService(name)
        self.assertEqual(code, 0)

        self.service_list_.remove(name)

        # Make sure the service no longer exists, error code 1060
        (code, _) = queryService(name)
        self.assertEqual(code, 1060)

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

        # Ensure that even if events fail we always remove the services
        if len(self.service_list_) > 0:
            for s in self.service_list_:
                stopService(s)
                test_base.expectTrue(serviceDead)
                uninstallService(s)


if __name__ == '__main__':
    assertUserIsAdmin()
    with test_base.CleanChildProcesses():
        test_base.Tester().run()

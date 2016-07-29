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
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

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


def assertUserIsAdmin():
    if os.name != "nt":
        sys.exit(-1)
    try:
        os.listdir("\\Windows\\Temp")
    except WindowsError:
        sys.exit(-1)


def sc(*args):
    try:
        output = subprocess.check_output(["sc.exe"] + list(args))
        return True
    except subprocess.CalledProcessError:
        return False


def findOsquerydBinary():
    script_root = os.path.split(os.path.abspath(__file__))[0]
    build_root = os.path.abspath(os.path.join(script_root,
                                              "..",
                                              "..",
                                              "build",
                                              "windows10",
                                              "osquery"))
    path = os.path.join(build_root, "Release", "osqueryd.exe")
    if os.path.exists(path):
        return path
    path = os.path.join(build_root, "RelWithDebInfo", "osqueryd.exe")
    if os.path.exists(path):
        return path
    sys.exit(-1)


def installService(name, path):
    return sc("create", name, "binPath=", path)


def startService(name, *argv):
    args = ["start", name] + list(argv)
    return sc(*args)


def queryService(name):
    try:
        output = subprocess.check_output(["sc.exe", "query", name])
        return output.replace("  ", "")
    except subprocess.CalledProcessError:
        return ""


def stopService(name):
    return sc("stop", name)


def uninstallService(name):
    return sc("delete", name)


class OsquerydTest(unittest.TestCase):
    def setUp(self):
        username = os.getenv("USERNAME")
        self.tmp_dir = os.path.join(tempfile.gettempdir(),
                                    "osquery-test-python%s" % username)
        self.bin_path = findOsquerydBinary()

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

        os.mkdir(self.tmp_dir)

        self.pidfile = os.path.join(self.tmp_dir, "osquery.pidfile")
        self.log_path = os.path.join(self.tmp_dir, "log")
        self.database_path = os.path.join(self.tmp_dir, "osquery.db")
        self.config_path = os.path.join(self.tmp_dir, "osquery.conf")

        with open(self.config_path, "wb") as fd:
            fd.write(CONFIG_FILE)

    def runDaemon(self, *args):
        try:
            p = subprocess.Popen([self.bin_path] + list(args),
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

            start = time.time()
            while p.poll() is None:
                if time.time() - start > 5:
                    p.kill()
                    break

            return (p.stdout.read(), p.stderr.read())
        except subprocess.CalledProcessError:
            return ("", "")

    def testService(self):
        name = "osqueryd_test%d" % random.randint(0, 65535)
        self.assertTrue(installService(name, self.bin_path))

        status = startService(name,
                              "--allow_unsafe",
                              "--config_path", self.config_path,
                              "--database_path", self.database_path,
                              "--logger_path", self.log_path,
                              "--pidfile", self.pidfile)
        self.assertTrue(status)
        time.sleep(2)

        try:
            output = queryService(name)
            self.assertNotEqual(output.find("STATE: 4RUNNING"), -1)

            stdout, stderr = self.runDaemon("--allow_unsafe",
                                            "--config_path",
                                            self.config_path,
                                            "--database_path",
                                            self.database_path,
                                            "--logger_path",
                                            self.log_path,
                                            "--pidfile",
                                            self.pidfile)
            self.assertNotEqual(stderr.find("is already running"), -1)
        finally:
            if status:
                self.assertTrue(stopService(name))

            output = queryService(name)
            self.assertNotEqual(output.find("STATE: 1STOPPED"), -1)

            self.assertTrue(uninstallService(name))

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

if __name__ == "__main__":
    assertUserIsAdmin()

    unittest.main()

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

import unittest

# osquery-specific testing utils
import test_base

class WatchdogTests(test_base.ProcessGenerator, unittest.TestCase):
    def test_1_daemon_without_watchdog(self):
        config = test_base.CONFIG.copy()
        config["options"]["disable_watchdog"] = "true"
        config["options"]["disable_extensions"] = "true"
        daemon = self._run_daemon(config)
        self.assertTrue(daemon.isAlive())
        daemon.kill()

    def test_2_daemon_with_watchdog(self):
        config = test_base.CONFIG.copy()
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


if __name__ == '__main__':
    test_base.Tester().run()

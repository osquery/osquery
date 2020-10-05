#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import unittest
import docker
import requests

import test_base

exceptions = (docker.errors.ContainerError, docker.errors.ImageNotFound, docker.errors.APIError, requests.exceptions.ConnectionError)

class FsChangesTableTest(unittest.TestCase):
    def setUp(self):
        self.binary = test_base.getLatestOsqueryBinary('osqueryi')
        self.osqueryi = test_base.OsqueryWrapper(command=self.binary)
        self.client = None
        self.container = None
        try:
            self.client = docker.from_env()
            self.container = self.client.containers.run("ubuntu:18.04", command="tail -f /dev/null", detach=True);
            self.container.exec_run("touch xxx")
        except exceptions as e:
            print(f"Failed in creating test container: {e}") 

    def tearDown(self):
        if self.container:
            self.container.stop()
        if self.client:
            self.client.close()
    
    def testFsChangesTable(self):
        if not self.client or not self.container:
            print("WARNING: Issue in creating test docker container; Skipping docker_container_fs_changes table testing")
            return

        query = "select * from docker_container_fs_changes where id = '" + self.container.id + "';"
        result = self.osqueryi.run_query(query)
        self.assertTrue(len(result) > 0)
        self.assertTrue(any(row["id"] == self.container.id and row["path"] == "/xxx" and row["change_type"] == 'A' for row in result))

if __name__ == '__main__':
    test_base.Tester().run()


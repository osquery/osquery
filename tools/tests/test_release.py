#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import json
import os
import subprocess
import string
import unittest

# osquery-specific testing utils
import test_base
from utils import platform


def allowed_platform(qp):
    if qp in ["all", "any"]:
        return True
    if len(qp) == 0:
        return True
    return qp.find(platform()) >= 0


class ReleaseTests(test_base.QueryTester):
    @test_base.flaky
    def test_pack_queries(self):
        packs = {}
        PACKS_DIR = SOURCE_DIR + "/packs"
        for _, _, files in os.walk(PACKS_DIR):
            for name in files:
                with open(os.path.join(PACKS_DIR, name), 'r') as fh:
                    content = fh.read()
                    content = string.replace(content, "\\\n", "")
                    packs[name] = json.loads(content)
        for name, pack in packs.items():
            if "queries" not in pack:
                continue
            if "platform" in pack and not allowed_platform(pack["platform"]):
                continue
            queries = []
            for _, query in pack["queries"].items():
                qp = query["platform"] if "platform" in query else ""
                if allowed_platform(qp):
                    queries.append(query["query"])
            self._execute_set(queries)

    @unittest.skipIf(platform() == "windows",
                     "Windows not currently supported")
    def test_no_avx_instructions(self):
        # TODO: Add equivalent logic for Windows
        if platform() == "windows":
            tool = "dumpbin /disasm"
        if platform() == "darwin":
            tool = "otool -tV"
        else:
            tool = "objdump -d"
        proc = subprocess.call(
            "%s %s | grep vxorps" % (tool, self.binary), shell=True)
        # Require no AVX instructions
        self.assertEqual(proc, 1)

    @unittest.skipIf(platform() == "windows",
                     "Windows not currently supported")
    def test_no_local_link(self):
        # TODO: Add equivalent logic for Windows
        if platform() == "windows":
            tool = "dumpbin /imports"
        if platform() == "darwin":
            tool = "otool -L"
        else:
            tool = "ldd"
        proc = subprocess.call(
            "%s %s | grep /usr/local/" % (tool, self.binary), shell=True)
        # Require no local dynamic dependent links.
        self.assertEqual(proc, 1)


if __name__ == '__main__':
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    SOURCE_DIR = os.path.abspath(SCRIPT_DIR + "/../../")

    module = test_base.Tester()
    # Find and import the thrift-generated python interface
    test_base.loadThriftFromBuild(test_base.ARGS.build)
    module.run()

#!/usr/bin/env python2

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
from __future__ import unicode_literals

import sys
import shutil
import time
import argparse
import subprocess
import tempfile
from threading import Thread

try:
    from utils import *
except ImportError:
    print("Cannot import osquery testing utils from ./tools/tests")
    exit(1)


def run_daemon(proc, output):
    output[proc.pid] = profile_cmd("", proc=proc)


def audit(args):
    def _run_procs(start):
        procs = []
        for i in range(3):
            for j in range(100):
                procs.append(subprocess.Popen("sleep %d" % 1,
                                              shell=True,
                                              stderr=subprocess.PIPE,
                                              stdout=subprocess.PIPE))
        if not args["stat"]:
            print("Finished launching processes: duration %6.4fs" % (
                time.time() - start))
        for p in procs:
            p.communicate()

    proc = None
    thread = None
    results = {}
    if not args["baseline"]:
        # Start a daemon, which will modify audit rules
        test = args["run"]
        if "args" in args:
            test += " %s" % (args["args"])
        dbpath = tempfile.mkdtemp()
        test += " --database_path=%s" % (dbpath)
        proc = subprocess.Popen(test,
                                shell=True,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        if not args["stat"]:
            thread = Thread(target=run_daemon, args=(proc, results,))
            thread.start()
        time.sleep(1)

    # Run test applications to stress the audting (a fork bomb)
    start_time = time.time()
    _run_procs(start_time)
    end_time = time.time()

    # Clean up
    if not args["baseline"]:
        proc.kill()
        shutil.rmtree(dbpath)
        if not args["stat"]:
            thread.join()
            if proc.pid in results:
                print("cpu: %6.2f, memory: %d, util: %6.2f" % (
                    results[proc.pid]["cpu_time"],
                    results[proc.pid]["memory"],
                    results[proc.pid]["utilization"]))
        pass
    return end_time - start_time


def single(args):
    start_time = time.time()
    if ARGS.verbose:
        proc = subprocess.Popen(args, shell=True)
    else:
        proc = subprocess.Popen(args,
                                shell=True,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
    if ARGS.verbose:
        print("PID: %d" % (proc.pid))
    stdout, stderr = proc.communicate()
    end_time = time.time() - start_time
    if proc.returncode is not 0:
        if not ARGS.verbose:
            print(stdout)
            print(stderr)
        print("%s Test failed. (total %6.4fs)" % (
            red("FAILED"), end_time))
        sys.exit(proc.returncode)
    return end_time


def stress(args):
    """Small utility to run unittests several times."""
    times = []
    test = args["run"] if args["run"] is not None else ["make", "test"]
    for i in xrange(args["num"]):
        if args["audit"]:
            times.append(audit(args))
        else:
            times.append(single(test))
        if args["stat"]:
            print("%6.4f" % (times[-1]))
        else:
            print("%s Tests passed (%d/%d) rounds. (average %6.4fs) " % (
                green("PASSED"), i + 1, args["num"], sum(times) / len(times)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run tests many times")
    parser.add_argument("-n", "--num", type=int, default=50,
                        help="Number of times to run tests")
    parser.add_argument("-A", "--audit", action="store_true", default=False,
                        help="Perform exec/process auditing stress tests")
    parser.add_argument("--baseline", action="store_true", default=False,
                        help="Run baselines when stressing auditing")
    parser.add_argument("--args", default="",
                        help="Arguments to pass to test binary")
    parser.add_argument("--stat", action="store_true", default=False,
                        help="Only print numerical values")
    parser.add_argument("--verbose", action="store_true", default=False,
                        help="Do not consume stderr/stdout")
    parser.add_argument("run", nargs="?", help="Run specific test binary")
    ARGS = parser.parse_args()

    # A baseline was requested, first run baselines then normal.
    if ARGS.baseline:
        print("Running baseline tests...")
        stress(vars(ARGS))
        ARGS.baseline = False
        print("Finished. Running tests...")

    stress(vars(ARGS))

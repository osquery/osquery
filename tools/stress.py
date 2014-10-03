#!/usr/bin/env python

import time
import argparse
import subprocess
import sys

def lightred(msg):
    return "\033[1;31m %s \033[0m" % str(msg)

def red(msg):
    return "\033[41m\033[1;37m %s \033[0m" % str(msg)

def green(msg):
    return "\033[42m\033[1;37m %s \033[0m" % str(msg)

def main(args):
    times = []
    test = args["run"] if args["run"] is not None else ["make", "test"]
    for i in xrange(args["num"]):
        start_time = time.time()
        proc = subprocess.Popen(test,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        times.append(time.time() - start_time)
        if proc.returncode is not 0:
            print stdout
            print lightred(stderr)
            print "%s Test %d failed. (total %6.4fs)" % (
                red("FAILED"), i+1, sum(times))
            return proc.returncode
        print "%s Tests passed (%d/%d) rounds. (average %6.4fs) " % (
            green("PASSED"), i+1, args["num"], sum(times)/len(times))
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run tests many times")
    parser.add_argument("-n", "--num", type=int, default=50,
        help="Number of times to run tests")
    parser.add_argument("run", nargs="?", help="Run specific test binary")
    args = parser.parse_args()

    exit(main(vars(args)))

#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import json
import os
import subprocess
import sys
import time

try:
    import argparse
except ImportError:
    print("Cannot import argparse.")
    exit(1)

# Import the testing utils
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../tests/")

import utils

KB = 1024 * 1024
RANGES = {
    "colors": (utils.blue, utils.green, utils.yellow, utils.red),
    "utilization": (8, 20, 50),
    "cpu_time": (0.4, 1, 10),
    "memory": (8 * KB, 12 * KB, 24 * KB),
    "fds": (10, 20, 50),
    "duration": (0.8, 1, 3),
}


def check_leaks_linux(shell, query, count=1, supp_file=None):
    """Run valgrind using the shell and a query, parse leak reports."""
    suppressions = "" if supp_file is None else "--suppressions=%s" % supp_file
    cmd = [
        "valgrind",
        "--tool=memcheck",
        suppressions,
        shell,
        "--profile",
        "%d" % count,
        query,
        "--disable_extensions",
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, stderr = proc.communicate()
    summary = {
        "definitely": None,
        "indirectly": None,
        "possibly": None,
    }
    if args.verbose:
        print(stderr)
    for line in stderr.split("\n"):
        for key in summary:
            if line.find(key) >= 0:
                summary[key] = line.split(":")[1].strip()
    if summary["definitely"] is None:
        raise Exception("Could not execute valgrind correctly")
    return summary


def check_leaks_darwin(shell, query, count=1):
    # Run the shell with a --delay flag such that leaks can attach before exit.
    proc = subprocess.Popen(
        [shell, "--profile", str(count), "--profile_delay", "1", query],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    leak_checks = None
    while proc.poll() is None:
        # Continue to run leaks until the monitored shell exits.
        leaks = subprocess.Popen(
            ["leaks", "%s" % proc.pid],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = leaks.communicate()
        if args.verbose:
            print(stdout)
        try:
            for line in stdout.split(b"\n"):
                if line.find(b"total leaked bytes") >= 0:
                    leak_checks = line.split(b":")[1].strip()
        except:
            print("Encountered exception while running leaks:")
            print(stdout)
    return {"definitely": leak_checks.decode("utf-8")}


def check_leaks(shell, query, count=1, supp_file=None):
    if utils.platform() == "darwin":
        return check_leaks_darwin(shell, query, count=count)
    else:
        return check_leaks_linux(shell, query, count=count, supp_file=supp_file)


def profile_leaks(shell, queries, count=1, rounds=1, supp_file=None):
    report = {}
    for name, query in queries.items():
        print("Analyzing leaks in query: %s" % query)
        # Apply count (optionally run the query several times).
        summary = check_leaks(shell, query, count, supp_file)
        display = []
        for key in summary:
            output = summary[key]
            if output is not None and output[0] != "0":
                # Add some fun colored output if leaking.
                if key == "definitely":
                    output = utils.red(output)
                    report[name] = "LEAKING"
                if key == "indirectly":
                    output = utils.yellow(output)
                    report[name] = "WARNING"
            elif name not in report.keys():
                report[name] = "SAFE"
            display.append("%s: %s" % (key, output))
        print("  %s" % "; ".join(display))
    return report


def run_query(shell, query, timeout=0, count=1):
    """Execute the osqueryi shell in profile mode with a setup/teardown delay."""
    start_time = time.time()
    return utils.profile_cmd([
        shell,
        "--profile",
        str(count),
        "--profile_delay",
        "1",
        query,
        "--disable_extensions",
    ], timeout=timeout, count=count)


def summary_line(name, result):
    if not args.n:
        for key, v in result.items():
            print("%s" % (
                RANGES["colors"][v[0]]("%s:%s" % (
                    key[0].upper(), v[0]))),
                  end="")
        print(" ", end="")
    print("%s:" % name, end=" ")
    for key, v in result.items():
        print("%s: %s" % (key, v[1]), end=" ")
    print("")


def summary(results, display=False):
    """Map the results to simple thresholds."""
    def rank(value, ranges):
        for i, r in enumerate(ranges):
            if value < r:
                return i
        return len(ranges)

    summary_results = {}
    for name, result in results.items():
        failed = "exit" in result and result["exit"] > 0
        summary_result = {}
        for key in RANGES:
            if key == "colors":
                continue
            if key not in result:
                continue
            if failed:
                summary_result[key] = (len(RANGES["colors"]) - 1, -1)
            else:
                summary_result[key] = (rank(result[key], RANGES[key]),
                                       result[key])
        if display and not args.check:
            summary_line(name, summary_result)
        summary_results[name] = summary_result
    return summary_results


def profile(shell, queries, timeout=0, count=1, rounds=1):
    report = {}
    for name, query in queries.items():
        forced = True if name == "force" else False
        if not forced:
            print("Profiling query: %s" % query)
        results = {}
        for i in range(rounds):
            if forced:
                result = utils.profile_cmd(shell, shell=True,
                    timeout=timeout, count=count)
            else:
                result = run_query(shell, query, timeout=timeout, count=count)
            summary(
                {"%s (%d/%d)" % (name, i + 1, rounds): result}, display=True)
            # Store each result round to return an average.
            for k, v in result.items():
                results[k] = results.get(k, [])
                results[k].append(v)
        average_results = {}
        for k in results:
            average_results[k] = sum(results[k]) / len(results[k])
        report[name] = average_results
        if rounds > 1:
            summary({"%s   avg" % name: report[name]}, display=True)
    return report


def compare(profile1, profile2):
    """Compare two jSON profile outputs."""
    for table in profile1:
        if table not in profile2:
            # No comparison possible
            continue
        summary_line(table, profile1[table])
        summary_line(table, profile2[table])


def regress_check(profile1, profile2):
    regressed = False
    for table in profile1:
        if table not in profile2:
            continue
        for measure in profile1[table]:
            if profile2[table][measure][0] > profile1[table][measure][0]:
                print("%s %s has regressed (%s->%s)!" % (table, measure,
                                                         profile1[table][measure][0], profile2[table][measure][0]))
                regressed = True
    if not regressed:
        print("No regressions!")
        return 0
    return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "Profile osquery, individual tables, "
        "or a set of osqueryd config queries."
    ))
    parser.add_argument(
        "-n", action="store_true", default=False,
        help="Do not output colored ranks."
    )
    parser.add_argument(
        "--verbose", action="store_true", default=False, help="Be verbose.")
    parser.add_argument(
        "--leaks", default=False, action="store_true",
        help="Check for memory leaks instead of performance."
    )
    group = parser.add_argument_group("Query Options:")
    group.add_argument(
        "--restrict", metavar="LIST", default="",
        help="Limit to a list of comma-separated tables."
    )
    group.add_argument(
        "--tables", metavar="PATH", default="./specs",
        help="Path to the osquery table specs."
    )
    group.add_argument(
        "--config", metavar="FILE", default=None,
        help="Use scheduled queries from a config."
    )
    group.add_argument(
        "--pack", metavar="PACK", default=None,
        help="Use queries from an osquery pack."
    )
    group.add_argument(
        "--query", metavar="STRING", default=None,
        help="Profile a single query."
    )

    group = parser.add_argument_group("Run Options:")
    group.add_argument(
        "--timeout", metavar="N", default=0, type=int,
        help="Max seconds a query may run --count times."
    )
    group.add_argument(
        "--count", metavar="N", default=1, type=int,
        help="Run the query N times serially."
    )
    group.add_argument(
        "--rounds", metavar="N", default=1, type=int,
        help="Run the profile for N rounds and use the average."
    )
    group.add_argument(
        "--shell", metavar="PATH", default="./build/osquery/osqueryi",
        help="Path to osqueryi shell (./build/osquery/osqueryi)."
    )
    group.add_argument(
        "--force", action="store_true", default=False,
        help="Force run the target of shell",
    )

    group = parser.add_argument_group("Performance Options:")
    group.add_argument(
        "--output", metavar="FILE", default=None,
        help="Write JSON performance output to file."
    )
    group.add_argument(
        "--check", metavar="OLD_OUTPUT", nargs=1,
        help="Check regressions using an existing output."
    )
    group.add_argument(
        "--compare", metavar="FILE", nargs=2,
        help="Compare existing performance outputs (old, new)."
    )

    group = parser.add_argument_group("Memory Options:")
    group.add_argument(
        "--suppressions", metavar="SUPP", default="./tools/analysis/valgrind.supp",
        help="Add a suppressions files to memory leak checking (linux only)."
    )
    args = parser.parse_args()

    if args.compare:
        with open(args.compare[0]) as fh:
            profile1 = json.loads(fh.read())
        with open(args.compare[1]) as fh:
            profile2 = json.loads(fh.read())
        compare(profile1, profile2)
        exit(0)

    if args.check:
        with open(args.check[0]) as fh:
            profile1 = json.loads(fh.read())

    if not args.force and not os.path.exists(args.shell):
        print("Cannot find --shell: %s" % (args.shell))
        exit(1)
    if args.config is None and not os.path.exists(args.tables):
        print("Cannot find --tables: %s" % (args.tables))
        exit(1)

    queries = {}
    query_source = "<none provided>"

    if args.config is not None:
        query_source = args.config
        if not os.path.exists(args.config):
            print("Cannot find --config: %s" % (args.config))
            exit(1)
        queries = utils.queries_from_config(args.config)
        # Search queries in subdirectory ".d" based on the config filename
        if os.path.isdir(args.config + ".d"):
            for config_file in os.listdir(args.config + ".d"):
                queries.update(utils.queries_from_config(os.path.join(
                    args.config + ".d", config_file)))
    elif args.pack is not None:
        queries = utils.queries_from_pack(args.pack)
    elif args.query is not None:
        query_source = "--query"
        queries["manual"] = args.query
    elif args.force:
        queries["force"] = True
    else:
        query_source = args.tables
        queries = utils.queries_from_tables(args.tables, args.restrict)

    if len(queries) == 0:
        print("0 queries were loaded from %s" % query_source)
        exit(1)
    elif len(queries) == 1:
        print("%d query loaded from %s\n" % (len(queries), query_source))
    else:
        print("%d queries loaded from %s\n" % (len(queries), query_source))

    if args.leaks:
        results = profile_leaks(
            args.shell, queries, count=args.count,
            rounds=args.rounds, supp_file=args.suppressions
        )
    else:
        # Start the profiling!
        results = profile(
            args.shell, queries,
            timeout=args.timeout, count=args.count, rounds=args.rounds
        )

        # Only apply checking/regressions to performance, not leaks.
        if args.check:
            exit(regress_check(profile1, summary(results)))

    if args.output is not None:
        with open(args.output, "w") as fh:
            if args.leaks:
                # Leaks report does not need a summary view.
                fh.write(json.dumps(results, indent=1))
            else:
                fh.write(json.dumps(summary(results), indent=1))
        print("Wrote output summary: %s" % args.output)

    if args.leaks:
        for name in results.keys():
            if results[name] != "SAFE":
                sys.exit(1)
    sys.exit(0)

#!/usr/bin/env python
# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

try:
    import argparse
except ImportError:
    print ("Cannot import argparse.")
    print ("Try: sudo yum install python-argparse")
    exit(1)

import json
import os
import psutil
import subprocess
import sys
import time


def red(msg):
    return "\033[41m\033[1;30m %s \033[0m" % str(msg)


def yellow(msg):
    return "\033[43m\033[1;30m %s \033[0m" % str(msg)


def green(msg):
    return "\033[42m\033[1;30m %s \033[0m" % str(msg)


def blue(msg):
    return "\033[46m\033[1;30m %s \033[0m" % str(msg)

KB = 1024 * 1024
RANGES = {
    "colors": (blue, green, yellow, red),
    "utilization": (8, 20, 50),
    "cpu_time": (0.4, 1, 10),
    "memory": (8 * KB, 12 * KB, 24 * KB),
    "fds": (6, 12, 50),
    "duration": (0.8, 1, 3),
}


def queries_from_config(config_path):
    config = {}
    try:
        with open(config_path, "r") as fh:
            config = json.loads(fh.read())
    except Exception as e:
        print ("Cannot open/parse config: %s" % str(e))
        exit(1)
    if "scheduledQueries" not in config:
        print ("Config does not contain any scheduledQueries.")
        exit(0)
    queries = {}
    for query in config["scheduledQueries"]:
        queries[query["name"]] = query["query"]
    return queries


def queries_from_tables(path, restrict):
    """Construct select all queries from all tables."""
    # Let the caller limit the tables
    restrict_tables = [t.strip() for t in restrict.split(",")]

    tables = []
    for base, _, files in os.walk(path):
        for spec in files:
            spec_platform = os.path.basename(base)
            table_name = spec.split(".table", 1)[0]
            if spec_platform not in ["x", platform]:
                continue
            # Generate all tables to select from, with abandon.
            tables.append("%s.%s" % (spec_platform, table_name))

    if len(restrict) > 0:
        tables = [t for t in tables if t.split(".")[1] in restrict_tables]
    queries = {}
    for table in tables:
        queries[table] = "SELECT * FROM %s;" % table.split(".", 1)[1]
    return queries


def get_stats(p, interval=1):
    """Run psutil and downselect the information."""
    utilization = p.cpu_percent(interval=interval)
    return {
        "utilization": utilization,
        "counters": p.io_counters() if sys.platform != "darwin" else None,
        "fds": p.num_fds(),
        "cpu_times": p.cpu_times(),
        "memory": p.memory_info_ex(),
    }


def check_leaks_linux(shell, query, supp_file=None):
    """Run valgrind using the shell and a query, parse leak reports."""
    suppressions = "" if supp_file is None else "--suppressions=%s" % supp_file
    cmd = "valgrind --tool=memcheck %s %s --query=\"%s\"" % (
        suppressions, shell, query)
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, stderr = proc.communicate()
    summary = {
        "definitely": None,
        "indirectly": None,
        "possibly": None,
    }
    for line in stderr.split("\n"):
        for key in summary:
            if line.find(key) >= 0:
                summary[key] = line.split(":")[1].strip()
    return summary


def check_leaks_darwin(shell, query):
    # Run the shell with a --delay flag such that leaks can attach before exit.
    proc = subprocess.Popen([shell, "--query", query, "--delay", "1"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    leak_checks = None
    while proc.poll() is None:
        # Continue to run leaks until the monitored shell exits.
        leaks = subprocess.Popen(
            ["leaks", "%s" % proc.pid],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = leaks.communicate()
        try:
            for line in stdout.split("\n"):
                if line.find("total leaked bytes") >= 0:
                    leak_checks = line.split(":")[1].strip()
        except:
            print ("Encountered exception while running leaks:")
            print (stdout)
    return {"definitely": leak_checks}


def check_leaks(shell, query, supp_file=None):
    if sys.platform == "darwin":
        return check_leaks_darwin(shell, query)
    else:
        return check_leaks_linux(shell, query, supp_file=supp_file)


def profile_leaks(shell, queries, count=1, rounds=1, supp_file=None):
    report = {}
    for name, query in queries.iteritems():
        print ("Analyzing leaks in query: %s" % query)
        # Apply count (optionally run the query several times).
        summary = check_leaks(shell, query * count, supp_file)
        display = []
        for key in summary:
            output = summary[key]
            if output is not None and output[0] != "0":
                # Add some fun colored output if leaking.
                if key == "definitely":
                    output = red(output)
                if key == "indirectly":
                    output = yellow(output)
            display.append("%s: %s" % (key, output))
        print ("  %s" % "; ".join(display))
        report[name] = summary
    return report


def run_query(shell, query, timeout=0, count=1):
    """Execute the osquery run testing wrapper with a setup/teardown delay."""
    start_time = time.time()
    proc = subprocess.Popen(
        [shell, "--query", query, "--iterations", str(count),
            "--delay", "1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    p = psutil.Process(pid=proc.pid)

    delay = 0
    step = 0.5

    percents = []
    # Calculate the CPU utilization in intervals of 1 second.
    while p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
        try:
            stats = get_stats(p, step)
            percents.append(stats["utilization"])
        except psutil.AccessDenied:
            break
        delay += step
        if timeout > 0 and delay >= timeout + 2:
            proc.kill()
            break
    duration = time.time() - start_time - 2

    utilization = [percent for percent in percents if percent != 0]
    if len(utilization) == 0:
        avg_utilization = 0
    else:
        avg_utilization = sum(utilization) / len(utilization)

    return {
        "utilization": avg_utilization,
        "duration": duration,
        "memory": stats["memory"].rss,
        "user_time": stats["cpu_times"].user,
        "system_time": stats["cpu_times"].system,
        "cpu_time": stats["cpu_times"].user + stats["cpu_times"].system,
        "fds": stats["fds"],
    }


def summary_line(name, result):
    if not args.n:
        for key, v in result.iteritems():
            print ("%s" % (
                RANGES["colors"][v[0]]("%s:%s" % (
                    key[0].upper(), v[0]))),
                end="")
        print (" ", end="")
    print ("%s:" % name, end=" ")
    for key, v in result.iteritems():
        print ("%s: %s" % (key, v[1]), end=" ")
    print ("")


def summary(results, display=False):
    """Map the results to simple thresholds."""
    def rank(value, ranges):
        for i, r in enumerate(ranges):
            if value < r:
                return i
        return len(ranges)

    summary_results = {}
    for name, result in results.iteritems():
        summary_result = {}
        for key in RANGES:
            if key == "colors":
                continue
            if key not in result:
                continue
            summary_result[key] = (rank(result[key], RANGES[key]), result[key])
        if display and not args.check:
            summary_line(name, summary_result)
        summary_results[name] = summary_result
    return summary_results


def profile(shell, queries, timeout=0, count=1, rounds=1):
    report = {}
    for name, query in queries.iteritems():
        print ("Profiling query: %s" % query)
        results = {}
        for i in range(rounds):
            result = run_query(shell, query, timeout=timeout, count=count)
            summary(
                {"%s (%d/%d)" % (name, i + 1, rounds): result}, display=True)
            # Store each result round to return an average.
            for k, v in result.iteritems():
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
                print ("%s %s has regressed (%s->%s)!" % (table, measure,
                    profile1[table][measure][0], profile2[table][measure][0]))
                regressed = True
    if not regressed:
        print ("No regressions!")
        return 0
    return 1

if __name__ == "__main__":
    platform = sys.platform
    if platform == "linux2":
        platform = "linux"
    parser = argparse.ArgumentParser(description=(
        "Profile osquery, individual tables, "
        "or a set of osqueryd config queries."
    ))
    parser.add_argument(
        "-n", action="store_true", default=False,
        help="Do not output colored ranks."
    )
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
        "--tables", metavar="PATH", default="./osquery/tables/specs",
        help="Path to the osquery table specs."
    )
    group.add_argument(
        "--config", metavar="FILE", default=None,
        help="Use scheduled queries from a config."
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
        "--shell", metavar="PATH", default="./build/%s/tools/run" % (platform),
        help="Path to osquery run wrapper (./build/<sys>/tools/run)."
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
        "--suppressions", metavar="SUPP", default=None,
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

    if not os.path.exists(args.shell):
        print ("Cannot find --daemon: %s" % (args.shell))
        exit(1)
    if args.config is None and not os.path.exists(args.tables):
        print ("Cannot find --tables: %s" % (args.tables))
        exit(1)

    queries = {}
    if args.config is not None:
        if not os.path.exists(args.config):
            print ("Cannot find --config: %s" % (args.config))
            exit(1)
        queries = queries_from_config(args.config)
    elif args.query is not None:
        queries["manual"] = args.query
    else:
        queries = queries_from_tables(args.tables, args.restrict)

    if args.leaks:
        results = profile_leaks(
            args.shell, queries, count=args.count,
            rounds=args.rounds, supp_file=args.suppressions
        )
        exit(0)

    # Start the profiling!
    results = profile(
        args.shell, queries,
        timeout=args.timeout, count=args.count, rounds=args.rounds
    )

    if args.check:
        exit(regress_check(profile1, summary(results)))

    if args.output is not None and not args.summary:
        with open(args.output, "w") as fh:
            fh.write(json.dumps(summary(results), indent=1))

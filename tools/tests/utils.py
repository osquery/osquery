#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import json
import os
import sys
import time
import subprocess
import shutil
import re

def red(msg):
    return "\033[41m\033[1;30m %s \033[0m" % str(msg)


def lightred(msg):
    return "\033[1;31m%s\033[0m" % str(msg)


def yellow(msg):
    return "\033[43m\033[1;30m %s \033[0m" % str(msg)


def green(msg):
    return "\033[42m\033[1;30m %s \033[0m" % str(msg)


def blue(msg):
    return "\033[46m\033[1;30m %s \033[0m" % str(msg)


def read_config(path):
    with open(path, "r") as fh:
        return json.loads(fh.read())


def write_config(data={}, path=None):
    if path is None:
        path = data["options"]["config_path"]
    with open(path, "w") as fh:
        fh.write(json.dumps(data))


def reset_dir(p):
    # Note that files may be added concurrently.
    # If they are then either of these will fail.
    shutil.rmtree(p, ignore_errors=True)
    try:
        os.makedirs(p)
    except Exception:
        pass


def copy_file(f, d):
    shutil.copy(f, d)


def platform():
    platform = sys.platform
    if platform.find("linux") == 0:
        platform = "linux"
    return platform


def queries_from_config(config_path):
    config = {}
    rmcomment = re.compile('\/\*[\*A-Za-z0-9\n\s\.\{\}\'\/\\\:]+\*\/|\s+\/\/.*|^\/\/.*|\x5c\x5c\x0a')
    try:
        with open(config_path, "r") as fh:
            configcontent = fh.read()
            content = rmcomment.sub('',configcontent)
            config = json.loads(content)
    except Exception as e:
        print("Cannot open/parse config: %s" % str(e))
        exit(1)
    queries = {}
    if "schedule" in config:
        for name, details in config["schedule"].items():
            queries[name] = details["query"]
    if "packs" in config:
        for keys,values in config["packs"].items():
            # Check if it is an internal pack definition
            if type(values) is dict:
                for queryname, query in values["queries"].items():
                    queries["pack_" + queryname] = query["query"]
            else:
                with open(values) as fp:
                    packfile = fp.read()
                    packcontent = rmcomment.sub('', packfile)
                    packqueries = json.loads(packcontent)
                    for queryname, query in packqueries["queries"].items():
                        queries["pack_" + queryname] = query["query"]

    return queries


def queries_from_tables(path, restrict):
    """Construct select all queries from all tables."""
    # Let the caller limit the tables
    restrict_tables = [t.strip() for t in restrict.split(",")]
    spec_platform = platform()
    tables = []
    for base, _, files in os.walk(path):
        for spec in files:
            if spec[0] == '.' or spec in ["denylist"]:
                continue
            spec_platform = os.path.basename(base)
            table_name = spec.split(".table", 1)[0]
            if spec_platform not in ["specs", "posix", platform()]:
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
        "counters": p.io_counters() if platform() != "darwin" else None,
        "fds": p.num_fds() if platform() != "win32" else None,
        "cpu_times": p.cpu_times(),
        "memory": p.memory_info(),
    }


def profile_cmd(cmd, proc=None, shell=False, timeout=0, count=1):
    import psutil
    start_time = time.time()
    if proc is None:
        proc = subprocess.Popen(cmd,
                                shell=shell,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    p = psutil.Process(pid=proc.pid)

    delay = 0
    step = 0.5

    percents = []
    # Calculate the CPU utilization in intervals of 1 second.
    stats = {}
    while p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
        try:
            current_stats = get_stats(p, step)
            if (current_stats["memory"].rss == 0):
                break
            stats = current_stats
            percents.append(stats["utilization"])
        except psutil.AccessDenied:
            break
        except psutil.ZombieProcess:
            break
        except psutil.NoSuchProcess:
            break
        delay += step
        if timeout > 0 and delay >= timeout + 2:
            proc.kill()
            break

    # account for sleep(1) in profiling code
    duration = time.time() - start_time - 2
    duration = max(duration, 0)

    utilization = [percent for percent in percents if percent != 0]
    if len(utilization) == 0:
        avg_utilization = 0
    else:
        avg_utilization = sum(utilization) / len(utilization)

    if len(stats.keys()) == 0:
        raise Exception("No stats recorded, perhaps binary returns -1?")
    rval = {
        "utilization": avg_utilization,
        "duration": duration,
        "memory": stats["memory"].rss,
        "user_time": stats["cpu_times"].user,
        "system_time": stats["cpu_times"].system,
        "cpu_time": stats["cpu_times"].user + stats["cpu_times"].system,
        "exit": p.wait(),
    }

    if stats.get("fds") is not None:
        rval["fds"] = stats["fds"]
    return rval

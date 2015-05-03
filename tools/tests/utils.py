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

import json
import os
import sys

def red(msg):
    return "\033[41m\033[1;30m %s \033[0m" % str(msg)


def lightred(msg):
    return "\033[1;31m %s \033[0m" % str(msg)


def yellow(msg):
    return "\033[43m\033[1;30m %s \033[0m" % str(msg)


def green(msg):
    return "\033[42m\033[1;30m %s \033[0m" % str(msg)


def blue(msg):
    return "\033[46m\033[1;30m %s \033[0m" % str(msg)


def read_config(path):
    with open(path, "r") as fh:
        return json.loads(fh.read())


def write_config(data={}):
    with open(data["options"]["config_path"], "w") as fh:
        fh.write(json.dumps(data))

def queries_from_config(config_path):
    config = {}
    try:
        with open(config_path, "r") as fh:
            config = json.loads(fh.read())
    except Exception as e:
        print ("Cannot open/parse config: %s" % str(e))
        exit(1)
    queries = {}
    if "scheduledQueries" in config:
        for query in config["scheduledQueries"]:
            queries[query["name"]] = query["query"]
    if "schedule" in config:
        for name, details in config["schedule"].iteritems():
            queries[name] = details["query"]
    if len(queries) == 0:
        print ("Could not find a schedule/queries in config: %s" % config_path)
        exit(0)
    return queries


def queries_from_tables(path, restrict):
    """Construct select all queries from all tables."""
    # Let the caller limit the tables
    restrict_tables = [t.strip() for t in restrict.split(",")]
    platform = sys.platform if sys.platform is not "linux2" else "linux"
    tables = []
    for base, _, files in os.walk(path):
        for spec in files:
            if spec[0] == '.' or spec in ["blacklist"]:
                continue
            spec_platform = os.path.basename(base)
            table_name = spec.split(".table", 1)[0]
            if spec_platform not in ["specs", platform]:
                continue
            # Generate all tables to select from, with abandon.
            tables.append("%s.%s" % (spec_platform, table_name))

    if len(restrict) > 0:
        tables = [t for t in tables if t.split(".")[1] in restrict_tables]
    queries = {}
    for table in tables:
        queries[table] = "SELECT * FROM %s;" % table.split(".", 1)[1]
    return queries


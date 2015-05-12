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

import jinja2
import os
import sys


TEMPLATE_NAME = "amalgamation.cpp.in"
BEGIN_LINE = "/// BEGIN[GENTABLE]"
END_LINE = "/// END[GENTABLE]"


def usage(progname):
    """ print program usage """
    print(("Usage: %s /path/to/tables "
        "/path/to/generated output[_amalgamation.cpp]") % progname)
    return 1


def genTableData(filename):
    with open(filename, "rU") as fh:
        data = fh.read()
    begin_table = False
    table_data = []
    for line in data.split("\n"):
        if line.find(BEGIN_LINE) >= 0:
            begin_table = True
        elif line.find(END_LINE) >= 0:
            begin_table = False
        elif begin_table:
            table_data.append(line)
    if len(table_data) == 0:
        return None
    return "\n".join(table_data)


def main(argc, argv):
    if argc < 4:
        return usage(argv[0])
    specs = argv[1]
    directory = argv[2]
    name = argv[3]

    tables = []
    # Discover the output template, usually a black cpp file with includes.
    template = os.path.join(specs, "templates", TEMPLATE_NAME)
    with open(template, "rU") as fh:
        template_data = fh.read()

    for base, _, filenames in os.walk(os.path.join(directory,
            "tables_%s" % (name))):
        for filename in filenames:
            if filename == name:
                continue
            table_data = genTableData(os.path.join(base, filename))
            if table_data is not None:
                tables.append(table_data)

    amalgamation = jinja2.Template(template_data).render(
        tables=tables)
    output = os.path.join(directory, "%s_amalgamation.cpp" % name)
    try:
        os.makedirs(os.path.dirname(output))
    except:
        # Generated folder already exists
        pass
    with open(output, "w") as fh:
        fh.write(amalgamation)
    return 0


if __name__ == "__main__":
    exit(main(len(sys.argv), sys.argv))

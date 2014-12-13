#!/usr/bin/env python
# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import jinja2
import os
import sys


OUTPUT_NAME = "amalgamation.cpp"
BEGIN_LINE = "/// BEGIN[GENTABLE]"
END_LINE = "/// END[GENTABLE]"


def usage(progname):
    """ print program usage """
    print("Usage: %s /path/to/generated/tables output.cpp " % progname)
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
    if argc < 3:
        return usage(argv[0])

    specs = argv[1]
    directory = argv[2]

    tables = []
    template = os.path.join(specs, "templates", "%s.in" % OUTPUT_NAME)
    with open(template, "rU") as fh:
        template_data = fh.read()

    for base, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if filename == OUTPUT_NAME:
                continue
            table_data = genTableData(os.path.join(base, filename))
            if table_data is not None:
                tables.append(table_data)

    amalgamation = jinja2.Template(template_data).render(
        tables=tables)
    output = os.path.join(directory, OUTPUT_NAME)
    with open(output, "w") as fh:
        fh.write(amalgamation)
    return 0


if __name__ == "__main__":
    exit(main(len(sys.argv), sys.argv))

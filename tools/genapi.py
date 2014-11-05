#!/usr/bin/env python
# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
#from __future__ import print_function
from __future__ import unicode_literals

import argparse
import ast
import logging
import os
import sys

from gentable import Column, table_name, schema, implementation, table

# the log format for the logging module
LOG_FORMAT = "%(levelname)s [Line %(lineno)d]: %(message)s"

CANONICAL_PLATFORMS = {
	"x": "All Platforms",
	"darwin": "Darwin (Apple OS X)",
	"linux": "Ubuntu, CentOS",
}

TEMPLATE_API_DEFINITION = """
/** @jsx React.DOM */

'use strict';

var API = [
%s
];

module.exports = API;

"""

TEMPLATE_CATEGORY = """

  {name: "%s", tables: [%s
  ]}"""

TEMPLATE_TABLE = """

    {name: "%s", columns: [%s
    ]}"""

TEMPLATE_COLUMN = """
      {name: "%s", type: "%s", description: "%s", tables: "%s"}"""

def gen_api(api):
	categories = []
	for category, tables in api.iteritems():
		tables_output = []
		for table in tables:
			columns_output = []
			for column in table[1]:
				columns_output.append(TEMPLATE_COLUMN % (
					column[0], column[1], "", ""))
			tables_output.append(TEMPLATE_TABLE % (
				table[0], ", ".join(columns_output)))
		categories.append(TEMPLATE_CATEGORY % (
			category, ", ".join(tables_output)))
	return TEMPLATE_API_DEFINITION % (", ".join(categories))

def gen_spec(tree):
	exec(compile(tree, "<string>", "exec"))
	schema = [(column.name, column.type) for column in table.schema]
	return (table.table_name, schema, table.function)

def main(argc, argv):
	parser = argparse.ArgumentParser("Generate API documentation.")
	parser.add_argument("--tables", default="osquery/tables/specs",
		help="Path to osquery table specs")
	args = parser.parse_args()

	logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

	if not os.path.exists(args.tables):
		logging.error("Cannot find path: %s" % args.table)
		exit(1)

	categories = {}
	for base, folders, files in os.walk(args.tables):
		for spec in files:
			platform = CANONICAL_PLATFORMS[os.path.basename(base)]
			name = spec.split(".table", 1)[0]
			if platform not in categories.keys():
				categories[platform] = []
			with open(os.path.join(base, spec), "rU") as fh:
				tree = ast.parse(fh.read())
				categories[platform].append(gen_spec(tree))
	print gen_api(categories)


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)


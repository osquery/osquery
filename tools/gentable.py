#!/usr/bin/env python
# Copyright 2004-present Facebook. All Rights Reserved.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ast
import jinja2
import logging
import os
import sys

# set DEVELOPING to True for debug statements
DEVELOPING = False

# the log format for the logging module
LOG_FORMAT = "%(levelname)s [Line %(lineno)d]: %(message)s"

# Read all implementation templates
TEMPLATES = {}

# Temporary reserved column names
RESERVED = ["group"]

# Supported SQL types for spec
class DataType(object):
    def __init__(self, affinity, cpp_type="std::string"):
        self.affinity = affinity
        self.type = cpp_type
    def __repr__(self):
        return self.affinity

TEXT = DataType("TEXT")
DATE = DataType("TEXT")
DATETIME = DataType("TEXT")
INTEGER = DataType("INTEGER", "int")
BIGINT = DataType("BIGINT", "long long int")

def usage():
    """ print program usage """
    print("Usage: %s <spec.table> <file.cpp> [disable_blacklist]" % sys.argv[0])

def to_camel_case(snake_case):
    """ convert a snake_case string to camelCase """
    components = snake_case.split('_')
    return components[0] + "".join(x.title() for x in components[1:])

def lightred(msg):
    return "\033[1;31m %s \033[0m" % str(msg)

def is_blacklisted(path, table_name):
    """Allow blacklisting by tablename."""
    specs_path = os.path.dirname(os.path.dirname(path))
    blacklist_path = os.path.join(specs_path, "blacklist")
    if not os.path.exists(blacklist_path):
        return False
    try:
        with open(blacklist_path, "r") as fh:
            blacklist = [line.strip() for line in fh.read().split("\n")
                if len(line.strip()) > 0 and line.strip()[0] != "#"]
            if table_name in blacklist:
                return True
    except:
        # Blacklist is not readable.
        pass
    return False

def setup_templates(path):
    tables_path = os.path.dirname(os.path.dirname(os.path.dirname(path)))
    templates_path = os.path.join(tables_path, "templates")
    if not os.path.exists(templates_path):
        print ("Cannot read templates path: %s" % (templates_path))
        exit(1)
    for template in os.listdir(os.path.join(tables_path, "templates")):
        template_name = template.split(".", 1)[0]
        with open(os.path.join(templates_path, template), "rb") as fh:
            TEMPLATES[template_name] = fh.read().replace("\\\n", "")

class Singleton(object):
    """
    Make sure that anything that subclasses Singleton can only be instantiated
    once
    """

    _instance = None

    def __new__(self, *args, **kwargs):
        if not self._instance:
            self._instance = super(Singleton, self).__new__(
                self, *args, **kwargs)
        return self._instance

class TableState(Singleton):
    """
    Maintain the state of of the table commands during the execution of
    the config file
    """

    def __init__(self):
        self.table_name = ""
        self.schema = []
        self.header = ""
        self.impl = ""
        self.function = ""
        self.class_name = ""
        self.description = ""

    def columns(self):
        return [i for i in self.schema if isinstance(i, Column)]

    def foreign_keys(self):
        return [i for i in self.schema if isinstance(i, ForeignKey)]

    def generate(self, path, template="default"):
        """Generate the virtual table files"""
        logging.debug("TableState.generate")
        self.impl_content = jinja2.Template(TEMPLATES[template]).render(
            table_name=self.table_name,
            table_name_cc=to_camel_case(self.table_name),
            schema=self.columns(),
            header=self.header,
            impl=self.impl,
            function=self.function,
            class_name=self.class_name
        )

        # Check for reserved column names
        for column in self.columns():
            if column.name in RESERVED:
                print (lightred(("Cannot use column name: %s in table: %s "
                    "(the column name is reserved)" % (
                        column.name, self.table_name))))
                exit(1)

        path_bits = path.split("/")
        for i in range(1, len(path_bits)):
            dir_path = ""
            for j in range(i):
                dir_path += "%s/" % path_bits[j]
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
        logging.debug("generating %s" % path)
        with open(path, "w+") as file_h:
            file_h.write(self.impl_content)

    def blacklist(self, path):
        print (lightred("Blacklisting generated %s" % path))
        logging.debug("blacklisting %s" % path)
        self.generate(path, template="blacklist")

table = TableState()

class Column(object):
    """
    Part of an osquery table schema.
    Define a column by name and type with an optional description to assist
    documentation generation and reference.
    """
    def __init__(self, name, col_type, description="", **kwargs):
        self.name = name
        self.type = col_type
        self.description = description

class ForeignKey(object):
    """
    Part of an osquery table schema.
    Loosely define a column in a table spec as a Foreign key in another table.
    """
    def __init__(self, **kwargs):
        self.column = kwargs.get("column", "")
        self.table = kwargs.get("table", "")

def table_name(name):
    """define the virtual table name"""
    logging.debug("- table_name")
    logging.debug("  - called with: %s" % name)
    table.table_name = name
    table.description = ""

def schema(schema_list):
    """
    define a list of Column object which represent the columns of your virtual
    table
    """
    logging.debug("- schema")
    for it in schema_list:
        if isinstance(it, Column):
            logging.debug("  - column: %s (%s)" % (it.name, it.type))
        if isinstance(it, ForeignKey):
            logging.debug("  - foreign_key: %s (%s)" % (it.column, it.table))
    table.schema = schema_list

def implementation(impl_string):
    """
    define the path to the implementation file and the function which
    implements the virtual table. You should use the following format:

      # the path is "osquery/table/implementations/foo.cpp"
      # the function is "QueryData genFoo();"
      implementation("foo@genFoo")
    """
    logging.debug("- implementation")
    filename, function = impl_string.split("@")
    class_parts = function.split("::")[::-1]
    function = class_parts[0]
    class_name = class_parts[1] if len(class_parts) > 1 else ""
    impl = "%s.cpp" % filename
    logging.debug("  - impl => %s" % impl)
    logging.debug("  - function => %s" % function)
    logging.debug("  - class_name => %s" % class_name)
    table.impl = impl
    table.function = function
    table.class_name = class_name

def description(text):
    table.description = text

def main(argc, argv):
    if DEVELOPING:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    if argc < 3:
        usage()
        sys.exit(1)

    filename = argv[1]
    output = argv[2]

    # Adding a 3rd parameter will enable the blacklist
    disable_blacklist = argc > 3

    setup_templates(filename)
    with open(filename, "rU") as file_handle:
        tree = ast.parse(file_handle.read())
        exec(compile(tree, "<string>", "exec"))
        if not disable_blacklist and is_blacklisted(filename, table.table_name):
            table.blacklist(output)
        else:
            table.generate(output)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

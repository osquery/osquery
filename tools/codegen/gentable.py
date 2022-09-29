#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import argparse
import ast
import fnmatch
import logging
import os
import sys

import templite

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# the log format for the logging module
LOG_FORMAT = "%(levelname)s [Line %(lineno)d]: %(message)s"

# Read all implementation templates
TEMPLATES = {}

# Temporary reserved column names
RESERVED = ["n", "index"]

# Set the platform in osquery-language. This is duplicated with
# tests/utils.py, but that duplication allows usage to _not_ require a
# build
def platform():
    platform = sys.platform
    if platform.find("linux") == 0:
        platform = "linux"
    return platform

PLATFORM = platform()

# Supported SQL types for spec
class DataType(object):
    def __init__(self, affinity, cpp_type="std::string"):
        '''A column datatype is a pair of a SQL affinity to C++ type.'''
        self.affinity = affinity
        self.type = cpp_type

    def __repr__(self):
        return self.affinity

# Define column-type MACROs for the table specs
TEXT = DataType("TEXT_TYPE")
DATE = DataType("TEXT_TYPE")
DATETIME = DataType("TEXT_TYPE")
INTEGER = DataType("INTEGER_TYPE", "int")
BIGINT = DataType("BIGINT_TYPE", "long long int")
UNSIGNED_BIGINT = DataType("UNSIGNED_BIGINT_TYPE", "long long unsigned int")
DOUBLE = DataType("DOUBLE_TYPE", "double")
BLOB = DataType("BLOB_TYPE", "Blob")

# Define table-category MACROS from the table specs
UNKNOWN = "UNKNOWN"
UTILITY = "UTILITY"
SYSTEM = "SYSTEM"
NETWORK = "NETWORK"
EVENTS = "EVENTS"
APPLICATION = "APPLICATION"

# This should mimic the C++ enumeration ColumnOptions in table.h
COLUMN_OPTIONS = {
    "index": "INDEX",
    "additional": "ADDITIONAL",
    "required": "REQUIRED",
    "optimized": "OPTIMIZED",
    "hidden": "HIDDEN",
    "collate_nocase": "COLLATENOCASE",
}

# Column options that render tables uncacheable.
NON_CACHEABLE = [
    "REQUIRED",
    "ADDITIONAL",
    "OPTIMIZED",
]

TABLE_ATTRIBUTES = {
    "event_subscriber": "EVENT_BASED",
    "user_data": "USER_BASED",
    "cacheable": "CACHEABLE",
    "utility": "UTILITY",
    "kernel_required": "KERNEL_REQUIRED", # Deprecated
}

WINDOWS = ['windows', 'win32', 'cygwin']
LINUX = ['linux']
POSIX = ['linux', 'darwin']
DARWIN = ['darwin']

def to_camel_case(snake_case):
    """ convert a snake_case string to camelCase """
    components = snake_case.split('_')
    return components[0] + "".join(x.title() for x in components[1:])

def to_upper_camel_case(snake_case):
    """ convert a snake_case string to UpperCamelCase """
    components = snake_case.split('_')
    return "".join(x.title() for x in components)

def lightred(msg):
    return "\033[1;31m %s \033[0m" % str(msg)


def is_denylisted(table_name, path=None, denylist=None):
    """Allow denylisting by tablename."""
    if denylist is None:
        specs_path = os.path.dirname(path)
        if os.path.basename(specs_path) != "specs":
            specs_path = os.path.dirname(specs_path)
        denylist_path = os.path.join(specs_path, "denylist")
        if not os.path.exists(denylist_path):
            return False
        try:
            with open(denylist_path, "r") as fh:
                denylist = [
                    line.strip() for line in fh.read().split("\n")
                    if len(line.strip()) > 0 and line.strip()[0] != "#"
                ]
        except:
            # Denylist is not readable.
            return False
    if not denylist:
        return False

    # table_name based denylisting!
    for item in denylist:
        item = item.split(":")
        # If this item is restricted to a platform and the platform
        # and table name match
        if len(item) > 1 and PLATFORM == item[0] and table_name == item[1]:
            return True
        elif len(item) == 1 and table_name == item[0]:
            return True
    return False


def setup_templates(templates_path):
    if not os.path.exists(templates_path):
        templates_path = os.path.join(
            os.path.dirname(tables_path), "templates")
        if not os.path.exists(templates_path):
            print("Cannot read templates path: %s" % (templates_path))
            exit(1)
    templates = (f for f in os.listdir(templates_path) if fnmatch.fnmatch(f, "*.in"))
    for template in templates:
        template_name = template.split(".", 1)[0]
        with open(os.path.join(templates_path, template), "r") as fh:
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
        self.attributes = {}
        self.examples = []
        self.notes = ""
        self.aliases = []
        self.fuzz_paths = []
        self.has_options = False
        self.has_column_aliases = False
        self.strongly_typed_rows = False
        self.generator = False

    def columns(self):
        return [i for i in self.schema if isinstance(i, Column)]

    def foreign_keys(self):
        return [i for i in self.schema if isinstance(i, ForeignKey)]

    def generate(self, path, template="default"):
        """Generate the virtual table files"""
        logging.debug("TableState.generate")

        all_options = []
        # Create a list of column options from the kwargs passed to the column.
        for column in self.columns():
            column_options = []
            for option in column.options:
                # Only allow explicitly-defined options.
                if option in COLUMN_OPTIONS:
                    column_options.append("ColumnOptions::" + COLUMN_OPTIONS[option])
                    all_options.append(COLUMN_OPTIONS[option])
                else:
                    print(yellow(
                        "Table %s column %s contains an unknown option: %s" % (
                            self.table_name, column.name, option)))
            column.options_set = " | ".join(column_options)
            if len(column.aliases) > 0:
                self.has_column_aliases = True
        if len(all_options) > 0:
            self.has_options = True
        if "event_subscriber" in self.attributes:
            self.generator = True
        if "strongly_typed_rows" in self.attributes:
            self.strongly_typed_rows = True
        if "cacheable" in self.attributes:
            if self.generator:
                print(lightred(
                    "Table cannot use a generator and be marked cacheable: %s" % (path)))
                exit(1)
        if self.table_name == "" or self.function == "":
            print(lightred("Invalid table spec: %s" % (path)))
            exit(1)

        # Check for reserved column names
        for column in self.columns():
            if column.name in RESERVED:
                print(lightred(("Cannot use column name: %s in table: %s "
                                "(the column name is reserved)" % (
                                    column.name, self.table_name))))
                exit(1)

        path_bits = path.split("/")
        for i in range(1, len(path_bits)):
            dir_path = ""
            for j in range(i):
                dir_path += "%s/" % path_bits[j]
            if not os.path.exists(dir_path):
                try:
                    os.mkdir(dir_path)
                except:
                    # May encounter a race when using a make jobserver.
                    pass
        logging.debug("generating %s" % path)
        self.impl_content = templite.Templite(TEMPLATES[template]).render(
            table_name=self.table_name,
            table_name_cc=to_camel_case(self.table_name),
            table_name_ucc=to_upper_camel_case(self.table_name),
            schema=self.columns(),
            header=self.header,
            impl=self.impl,
            function=self.function,
            class_name=self.class_name,
            attributes=self.attributes,
            examples=self.examples,
            aliases=self.aliases,
            has_options=self.has_options,
            has_column_aliases=self.has_column_aliases,
            generator=self.generator,
            strongly_typed_rows=self.strongly_typed_rows,
            attribute_set=[TABLE_ATTRIBUTES[attr] for attr in self.attributes if attr in TABLE_ATTRIBUTES],
        )

        with open(path, "w+") as file_h:
            file_h.write(self.impl_content)

    def denylist(self, path):
        print(lightred("Denylisting generated %s" % path))
        logging.debug("denylisting %s" % path)
        self.generate(path, template="denylist")

table = TableState()


class Column(object):

    """
    Part of an osquery table schema.
    Define a column by name and type with an optional description to assist
    documentation generation and reference.
    """

    def __init__(self, name, col_type, description="", aliases=[], platforms=[], notes="", **kwargs):
        self.name = name
        self.type = col_type
        self.description = description
        self.aliases = aliases
        self.platforms = platforms
        self.notes = notes
        self.options = kwargs


class ForeignKey(object):

    """
    Part of an osquery table schema.
    Loosely define a column in a table spec as a Foreign key in another table.
    """

    def __init__(self, **kwargs):
        self.column = kwargs.get("column", "")
        self.table = kwargs.get("table", "")


def table_name(name, aliases=[]):
    """define the virtual table name"""
    logging.debug("- table_name")
    logging.debug("  - called with: %s" % name)
    table.table_name = name
    table.description = ""
    table.attributes = {}
    table.examples = []
    table.notes = ""
    table.aliases = aliases


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


def extended_schema(platforms, schema_list):
    """
    define a comparator and a list of Columns objects.
    """
    logging.debug("- extended schema")
    for it in schema_list:
        if isinstance(it, Column):
            logging.debug("  - column: %s (%s)" % (it.name, it.type))
            it.platforms = platforms
            if not PLATFORM in platforms:
                it.options['hidden'] = True
            table.schema.append(it)


def description(text):
    if text[-1:] != '.':
        print(lightred("Table description must end with a period!"))
        exit(1)
    table.description = text


def select_all(name=None):
    if name is None:
        name = table.table_name
    return "select count(*) from %s;" % (name)


def examples(example_queries):
    table.examples = example_queries

def notes(table_notes):
    table.notes = table_notes

def attributes(**kwargs):
    for attr in kwargs:
        table.attributes[attr] = kwargs[attr]


def fuzz_paths(paths):
    table.fuzz_paths = paths


def implementation(impl_string, generator=False):
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
    table.generator = generator

    '''Check if the table has a subscriber attribute, if so, enforce time.'''
    if "event_subscriber" in table.attributes:
        if not table.table_name.endswith("_events"):
            print(lightred("Event subscriber must use a '_events' suffix"))
            sys.exit(1)
        columns = {}
        # There is no dictionary comprehension on all supported platforms.
        for column in table.schema:
            if isinstance(column, Column):
                columns[column.name] = column.type
        if "time" not in columns:
            print(lightred("Event subscriber: %s needs a 'time' column." % (
                table.table_name)))
            sys.exit(1)
        if columns["time"] is not BIGINT:
            print(lightred(
                "Event subscriber: %s, 'time' column must be a %s type" % (
                    table.table_name, BIGINT)))
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        "Generate C++ Table Plugin from specfile.")
    parser.add_argument(
        "--debug", default=False, action="store_true",
        help="Output debug messages (when developing)"
    )
    parser.add_argument("--disable-denylist", default=False,
        action="store_true")
    parser.add_argument("--header", default=False, action="store_true",
                        help="Generate the header file instead of cpp")
    parser.add_argument("--foreign", default=False, action="store_true",
        help="Generate a foreign table")
    parser.add_argument("--templates", default=SCRIPT_DIR + "/templates",
                        help="Path to codegen output .cpp.in templates")
    parser.add_argument("spec_file", help="Path to input .table spec file")
    parser.add_argument("output", help="Path to output .cpp file")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    filename = args.spec_file
    output = args.output
    if filename.endswith(".table"):
        # Adding a 3rd parameter will enable the denylist

        setup_templates(args.templates)
        with open(filename, "r") as file_handle:
            tree = ast.parse(file_handle.read())
            exec(compile(tree, "<string>", "exec"))
            denylisted = is_denylisted(table.table_name, path=filename)
            if not args.disable_denylist and denylisted:
                table.denylist(output)
            else:
                if args.header:
                    template_type = "typed_row"
                elif args.foreign:
                    template_type = "foreign"
                else:
                    template_type = "default"
                table.generate(output, template=template_type)

if __name__ == "__main__":
    main()

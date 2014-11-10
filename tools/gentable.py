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

# BL_IMPL_TEMPLATE is the jinja template used to generate the virtual table
# implementation file when the table is blacklisted in ./osquery/tables/specs
BL_IMPL_TEMPLATE = """// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

void __blacklisted_{{table_name}}() {}

"""

# IMPL_TEMPLATE is the jinja template used to generate the virtual table
# implementation file
IMPL_TEMPLATE = """// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#include <cstring>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "osquery/database.h"
#include "osquery/tables/base.h"
#include "osquery/registry/registry.h"

namespace osquery { namespace tables {

{% if class_name == "" %}
osquery::QueryData {{function}}();
{% else %}
class {{class_name}} {
 public:
  static osquery::QueryData {{function}}();
};
{% endif %}

struct sqlite3_{{table_name}} {
  int n;
{% for col in schema %}\
  std::vector<{{col.type}}> {{col.name}};
{% endfor %}\
};

const std::string
  sqlite3_{{table_name}}_create_table_statement =
  "CREATE TABLE {{table_name}}("
  {% for col in schema %}\
  "{{col.name}} \
{% if col.type == "std::string" %}VARCHAR{% endif %}\
{% if col.type == "int" %}INTEGER{% endif %}\
{% if col.type == "long long int" %}BIGINT{% endif %}\
{% if not loop.last %}, {% endif %}"
  {% endfor %}\
")";

int {{table_name_cc}}Create(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
) {
  return xCreate<
    x_vtab<sqlite3_{{table_name}}>,
    sqlite3_{{table_name}}
  >(
    db, pAux, argc, argv, ppVtab, pzErr,
    sqlite3_{{table_name}}_create_table_statement.c_str()
  );
}

int {{table_name_cc}}Column(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
) {
  base_cursor *pCur = (base_cursor*)cur;
  x_vtab<sqlite3_{{table_name}}> *pVtab =
    (x_vtab<sqlite3_{{table_name}}>*)cur->pVtab;

  if(pCur->row >= 0 && pCur->row < pVtab->pContent->n) {
    switch (col) {
{% for col in schema %}\
      // {{ col.name }}
      case {{ loop.index0 }}:
{% if col.type == "std::string" %}\
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->{{col.name}}[pCur->row]).c_str(),
          -1,
          nullptr
        );
{% endif %}\
{% if col.type == "int" %}\
        sqlite3_result_int(
          ctx,
          (int)pVtab->pContent->{{col.name}}[pCur->row]
        );
{% endif %}\
{% if col.type == "long long int" %}\
        sqlite3_result_int64(
          ctx,
          (long long int)pVtab->pContent->{{col.name}}[pCur->row]
        );
{% endif %}\
        break;
{% endfor %}\
    }
  }
  return SQLITE_OK;
}

int {{table_name_cc}}Filter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  x_vtab<sqlite3_{{table_name}}> *pVtab =
    (x_vtab<sqlite3_{{table_name}}>*)pVtabCursor->pVtab;

  pCur->row = 0;
{% for col in schema %}\
  pVtab->pContent->{{col.name}}.clear();
{% endfor %}\

{% if class_name != "" %}
  for (auto& row : osquery::tables::{{class_name}}::{{function}}()) {
{% else %}
  for (auto& row : osquery::tables::{{function}}()) {
{% endif %}
{% for col in schema %}\
{% if col.type == "std::string" %}\
    pVtab->pContent->{{col.name}}.push_back(row["{{col.name}}"]);
{% endif %}\
{% if col.type == "int" %}\
    try {
      pVtab->pContent->{{col.name}}\
.push_back(boost::lexical_cast<int>(row["{{col.name}}"]));
    } catch (const boost::bad_lexical_cast& e) {
      LOG(WARNING) << "Error casting " << row["{{col.name}}"] << " to int";
      pVtab->pContent->{{col.name}}.push_back(-1);
    }
{% endif %}\
{% if col.type == "long long int" %}\
    try {
      pVtab->pContent->{{col.name}}\
.push_back(boost::lexical_cast<long long>(row["{{col.name}}"]));
    } catch (const boost::bad_lexical_cast& e) {
      LOG(WARNING) << "Error casting " << row["{{col.name}}"] << " to long long int";
      pVtab->pContent->{{col.name}}.push_back(-1);
    }
{% endif %}\
{% endfor %}\
  }

  pVtab->pContent->n = pVtab->pContent->{{schema[0].name}}.size();

  return SQLITE_OK;
}

static sqlite3_module {{table_name_cc}}Module = {
  0,
  {{table_name_cc}}Create,
  {{table_name_cc}}Create,
  xBestIndex,
  xDestroy<x_vtab<sqlite3_{{table_name}}>>,
  xDestroy<x_vtab<sqlite3_{{table_name}}>>,
  xOpen<base_cursor>,
  xClose<base_cursor>,
  {{table_name_cc}}Filter,
  xNext<base_cursor>,
  xEof<base_cursor, x_vtab<sqlite3_{{table_name}}>>,
  {{table_name_cc}}Column,
  xRowid<base_cursor>,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
};

class {{table_name_cc}}TablePlugin : public TablePlugin {
public:
  {{table_name_cc}}TablePlugin() {}

  int attachVtable(sqlite3 *db) {
    return sqlite3_attach_vtable<sqlite3_{{table_name}}>(
      db, "{{table_name}}", &{{table_name_cc}}Module);
  }

  virtual ~{{table_name_cc}}TablePlugin() {}
};

REGISTER_TABLE(
  "{{table_name}}",
  std::make_shared<{{table_name_cc}}TablePlugin>()
);

}}

"""

def usage():
    """ print program usage """
    print("Usage: %s <spec.table> <file.cpp> [use_blacklist]" % sys.argv[0])

def to_camel_case(snake_case):
    """ convert a snake_case string to camelCase """
    components = snake_case.split('_')
    return components[0] + "".join(x.title() for x in components[1:])

def lightred(msg):
    return "\033[1;31m %s \033[0m" % str(msg)

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

    def generate(self, path, template=IMPL_TEMPLATE):
        """Generate the virtual table files"""
        logging.debug("TableState.generate")
        self.impl_content = jinja2.Template(template).render(
            table_name=self.table_name,
            table_name_cc=to_camel_case(self.table_name),
            schema=self.columns(),
            header=self.header,
            impl=self.impl,
            function=self.function,
            class_name=self.class_name
        )

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
        self.generate(path, template=BL_IMPL_TEMPLATE)

table = TableState()

class Column(object):
    """
    Part of an osquery table schema.
    Define a column by name and type with an optional description to assist
    documentation generation and reference.
    """
    def __init__(self, **kwargs):
        self.name = kwargs.get("name", "")
        self.type = kwargs.get("type", "")
        self.description = kwargs.get("description", "")

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
    use_blacklist = argc > 3

    with open(filename, "rU") as file_handle:
        tree = ast.parse(file_handle.read())
        exec(compile(tree, "<string>", "exec"))
        if use_blacklist and is_blacklisted(filename, table.table_name):
            table.blacklist(output)
        else:
            table.generate(output)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)

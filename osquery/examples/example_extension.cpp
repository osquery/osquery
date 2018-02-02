/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sdk.h>
#include <osquery/system.h>

using namespace osquery;

class ExampleConfigPlugin : public ConfigPlugin {
 public:
  Status setUp() {
    LOG(WARNING) << "ExampleConfigPlugin setting up";
    return Status(0, "OK");
  }

  Status genConfig(std::map<std::string, std::string>& config) {
    config["data"] = "{\"queries\":{}}";
    return Status(0, "OK");
  }
};

static const TableDefinition tbl_example_def = {
    "example",
    {/* no aliases */},
    {
        std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple(
            "example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
    },
    {/* no columnAliases */},
    {/* no attributes */}};

class ExampleTable : public TablePlugin {
 public:
  ExampleTable() : TablePlugin(tbl_example_def) {}

 private:
  QueryData generate(QueryContext& request) {
    QueryData results;

    Row r;
    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);

    results.push_back(r);
    return results;
  }
};

static const TableDefinition tbl_complex_example_def = {
    "complex_example",
    {/* no aliases */},
    {
        std::make_tuple("flag_test", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("database_test", TEXT_TYPE, ColumnOptions::DEFAULT),
    },
    {/* no columnAliases */},
    {/* no attributes */}};

/**
 * @brief A more 'complex' example table is provided to assist with tests.
 *
 * This table will access options and flags known to the extension.
 * An extension should not assume access to any CLI flags- rather, access is
 * provided via the osquery-meta table: osquery_flags.
 *
 * There is no API/C++ wrapper to provide seamless use of flags yet.
 * We can force an implicit query to the manager though.
 *
 * Database access should be mediated by the *Database functions.
 * Direct use of the "database" registry will lead to undefined behavior.
 */
class ComplexExampleTable : public TablePlugin {
 public:
  ComplexExampleTable() : TablePlugin(tbl_complex_example_def) {}

 private:
  QueryData generate(QueryContext& request) {
    Row r;

    // Use the basic 'force' flag to check implicit SQL usage.
    auto flags =
        SQL("select default_value from osquery_flags where name = 'force'");
    if (flags.rows().size() > 0) {
      r["flag_test"] = flags.rows().back().at("default_value");
    }

    std::string content;
    setDatabaseValue(kPersistentSettings, "complex_example", "1");
    if (getDatabaseValue(kPersistentSettings, "complex_example", content)) {
      r["database_test"] = content;
    }

    return {r};
  }
};

REGISTER_EXTERNAL(ExampleConfigPlugin, "config", "example");
REGISTER_EXTERNAL(ExampleTable, "table", "example");
REGISTER_EXTERNAL(ComplexExampleTable, "table", "complex_example");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}

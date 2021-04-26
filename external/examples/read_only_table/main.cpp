/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

using namespace osquery;

class ExampleTable : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple(
            "example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableRows generate(QueryContext& request) {
    TableRows results;

    auto r = make_table_row();
    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);

    results.push_back(std::move(r));
    return results;
  }
};

REGISTER_EXTERNAL(ExampleTable, "table", "example");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return runner.shutdown(0);
}

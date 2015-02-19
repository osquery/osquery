/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/sdk.h>

using namespace osquery;

class ExampleTable : public tables::TablePlugin {
 private:
  tables::TableColumns columns() const {
    return {{"example_text", "TEXT"}, {"example_integer", "INTEGER"}};
  }

  QueryData generate(tables::QueryContext& request) {
    QueryData results;

    Row r;
    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);

    results.push_back(r);
    return results;
  }
};

REGISTER(ExampleTable, "table", "example");

int main(int argc, char* argv[]) {
  initOsquery(argc, argv, OSQUERY_EXTENSION);

  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
  }

  // Finally shutdown.
  shutdownOsquery();
  return 0;
}

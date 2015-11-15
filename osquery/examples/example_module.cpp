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

class ExampleTable : public TablePlugin {
 private:
  TableColumns columns() const {
    return {{"example_text", TEXT_TYPE}, {"example_integer", INTEGER_TYPE}};
  }

  QueryData generate(QueryContext& request) {
    QueryData results;

    Row r;
    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);

    results.push_back(r);
    return results;
  }
};

// Create the module if the environment variable TESTFAIL1 is not defined.
// This allows the integration tests to, at run time, test the module
// loading workflow.
CREATE_MODULE_IF(getenv("TESTFAIL1") == nullptr, "example", "0.0.1", "0.0.0");

void initModule(void) {
  // Register a plugin from a module if the environment variable TESTFAIL2
  // is not defined.
  if (getenv("TESTFAIL2") == nullptr) {
    REGISTER_MODULE(ExampleTable, "table", "example");
  }
}

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

class ExampleConfigPlugin : public ConfigPlugin {
 public:
  Status setUp() {
    LOG(WARNING) << "ExampleConfigPlugin setting up.";
    return Status(0, "OK");
  }

  Status genConfig(std::map<std::string, std::string>& config) {
    config["data"] = "{\"options\": [], \"scheduledQueries\": []}";
    return Status(0, "OK");
  }
};

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

REGISTER_EXTERNAL(ExampleConfigPlugin, "config", "example");
REGISTER_EXTERNAL(ExampleTable, "table", "example");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);

  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
  }

  // Finally shutdown.
  runner.shutdown();
  return 0;
}

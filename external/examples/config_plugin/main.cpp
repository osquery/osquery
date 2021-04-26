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

class ExampleConfigPlugin : public ConfigPlugin {
 public:
  Status setUp() {
    LOG(WARNING) << "ExampleConfigPlugin setting up";
    return Status::success();
  }

  Status genConfig(std::map<std::string, std::string>& config) {
    config["data"] = "{\"queries\":{}}";
    return Status::success();
  }
};

REGISTER_EXTERNAL(ExampleConfigPlugin, "config", "example");

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

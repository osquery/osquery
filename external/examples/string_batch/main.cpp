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

#include <chrono>
#include <iostream>
#include <thread>

using namespace osquery;

namespace {

class StringBatch final {
  rapidjson::Document doc;

  void initialize() {
    doc = {};
    doc.SetArray();
  }

 public:
  StringBatch() {
    initialize();
  }

  void append(const std::string& str) {
    rapidjson::Value value;
    value.SetString(str.c_str(), str.size(), doc.GetAllocator());

    doc.PushBack(value, doc.GetAllocator());
  }

  std::string take() {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    auto batch = buffer.GetString();
    initialize();

    return batch;
  }
};

} // namespace

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("string_batch_example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  StringBatch string_batch;
  int entry_number{};

  for (int i{0}; i < 10; ++i) {
    for (int k{0}; k < 10; ++k) {
      string_batch.append("This is item #" + std::to_string(entry_number));
      ++entry_number;
    }

    std::cout << "Sending batch #" << i << "\n";

    auto status = Registry::call(
        "logger", "filesystem", {{"string_batch", string_batch.take()}});

    if (!status.ok()) {
      std::cerr << "Failed to execute the logger::string_batch request\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(5));
  }

  runner.waitForShutdown();
  return runner.shutdown(0);
}

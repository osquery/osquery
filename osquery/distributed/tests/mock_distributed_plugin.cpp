/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sstream>
#include <vector>

#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

namespace osquery {

/**
 * @brief A class that can be used in unit tests to mock up
 * distributed read and write endpoints.  A test can set
 * the query and read the result.
 *
 */
class MockDistributedPlugin : public DistributedPlugin {
 public:
  MockDistributedPlugin()
      : DistributedPlugin(),
        read_value_(),
        writes_(),
        isReadEndpointEnabled_(true),
        isWriteEndpointEnabled_(true) {}

  Status setUp() override {
    return Status();
  }

  Status getQueries(std::string& json) override {
    if (!isReadEndpointEnabled_) {
      VLOG(1) << "getQueries : emulating endpoint DOWN";
      return Status(1, "Endpoint DOWN");
    }
    json = read_value_;
    VLOG(1) << "getQueries " << json;
    return Status();
  }

  Status writeResults(const std::string& json) override {
    if (!isWriteEndpointEnabled_) {
      VLOG(1) << "writeResults emulating endpoint DOWN";
      return Status(1, "Endpoint down");
    }
    VLOG(1) << "writeResults " << json;
    writes_.push_back(json);
    return Status();
  }

  Status call(const PluginRequest& request, PluginResponse& response) override {
    if (request.count("action") == 0) {
      return Status(1,
                    "Distributed plugins require an action in PluginRequest");
    }

    auto& action = request.at("action");

    if (action == "getQueries") {
      std::string queries;
      getQueries(queries);
      response.push_back({{"results", queries}});
      return Status();

    } else if (action == "writeResults") {
      if (request.count("results") == 0) {
        return Status(1, "Missing results field");
      }
      return writeResults(request.at("results"));

    } else if (action == "getMockWrites") {
      auto m = std::map<std::string, std::string>();
      for (size_t i = 0; i < writes_.size(); i++) {
        char idstr[32];
        snprintf(idstr, sizeof(idstr), "W_%d", (int)i);
        m[std::string(idstr)] = writes_[i];
      }
      response.push_back({m});
      return Status();

    } else if (action == "clearMockWrites") {
      writes_.clear();
      return Status();

    } else if (action == "setMockReadStatus") {
      isReadEndpointEnabled_ = (request.at("value") == "1");
      return Status();

    } else if (action == "setMockWriteStatus") {
      isWriteEndpointEnabled_ = (request.at("value") == "1");
      return Status();

    } else if (action == "setMockReadValue") {
      read_value_ = request.at("value");
      return Status();
    }

    return Status(1, "Distributed plugin action unknown: " + action);
  }

  std::string read_value_;
  std::vector<std::string> writes_;
  bool isReadEndpointEnabled_;
  bool isWriteEndpointEnabled_;
};

REGISTER(MockDistributedPlugin, "distributed", "mock");

} // namespace osquery

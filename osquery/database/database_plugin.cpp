/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/database_plugin.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/status.h>

#include <osquery/flags.h>

namespace osquery {

Status DatabasePlugin::reset() {
  // Keep this simple, scope the critical section to the broader methods.
  tearDown();
  return setUp();
}

Status DatabasePlugin::scan(const std::string& domain,
                            std::vector<std::string>& results,
                            const std::string& prefix,
                            size_t max) const {
  return Status(0, "Not used");
}

Status DatabasePlugin::call(const PluginRequest& request,
                            PluginResponse& response) {
  if (request.count("action") == 0) {
    return Status(1, "Database plugin must include a request action");
  }

  // Get a domain/key, which are used for most database plugin actions.
  auto domain = (request.count("domain") > 0) ? request.at("domain") : "";
  auto key = (request.count("key") > 0) ? request.at("key") : "";

  if (request.at("action") == "reset") {
    // Prevent RocksDB reentrancy by logger plugins during plugin setup.
    VLOG(1) << "Resetting the database plugin: " << getName();
    auto status = this->reset();
    if (!status.ok()) {
      // The active database could not be reset, fallback to an ephemeral.
      Registry::get().setActive("database", "ephemeral");
      LOG(WARNING) << "Unable to reset database plugin: " << getName();
    }
    return status;
  }

  // Switch over the possible database plugin actions.
  if (request.at("action") == "get") {
    std::string value;
    auto status = this->get(domain, key, value);
    response.push_back({{"v", value}});
    return status;
  } else if (request.at("action") == "put") {
    if (request.count("value") == 0) {
      return Status(1, "Database plugin put action requires a value");
    }
    return this->put(domain, key, request.at("value"));
  } else if (request.at("action") == "remove") {
    return this->remove(domain, key);
  } else if (request.at("action") == "remove_range") {
    auto key_high = (request.count("high") > 0) ? request.at("key_high") : "";
    if (!key_high.empty() && !key.empty()) {
      return this->removeRange(domain, key, key_high);
    }
    return Status(1, "Missing range");
  } else if (request.at("action") == "scan") {
    // Accumulate scanned keys into a vector.
    std::vector<std::string> keys;
    // Optionally allow the caller to request a max number of keys.
    size_t max = 0;
    if (request.count("max") > 0) {
      max = std::stoul(request.at("max"));
    }
    auto status = this->scan(domain, keys, request.at("prefix"), max);
    for (const auto& k : keys) {
      response.push_back({{"k", k}});
    }
    return status;
  }

  return Status(1, "Unknown database plugin action");
}

} // namespace osquery

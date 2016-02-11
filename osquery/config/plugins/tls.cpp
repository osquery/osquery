/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <sstream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/config.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/dispatcher/dispatcher.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"
#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {

CLI_FLAG(uint64,
         config_tls_max_attempts,
         3,
         "Number of attempts to retry a TLS config/enroll request");

/// Config retrieval TLS endpoint (path) using TLS hostname.
CLI_FLAG(string,
         config_tls_endpoint,
         "",
         "TLS/HTTPS endpoint for config retrieval");

/// Config polling/updating, only applies to TLS configurations.
CLI_FLAG(uint64,
         config_tls_refresh,
         0,
         "Optional interval in seconds to re-read configuration");

DECLARE_bool(tls_secret_always);
DECLARE_string(tls_enroll_override);
DECLARE_bool(tls_node_api);

class TLSConfigPlugin;

class TLSConfigPlugin : public ConfigPlugin,
                        std::enable_shared_from_this<TLSConfigPlugin> {
 public:
  Status setUp() override;
  Status genConfig(std::map<std::string, std::string>& config) override;

 protected:
  /// Calculate the URL once and cache the result.
  std::string uri_;
};

class TLSConfigRefreshRunner : public InternalRunnable {
 public:
  /// A simple wait/interruptible lock.
  void start();
};

REGISTER(TLSConfigPlugin, "config", "tls");

Status TLSConfigPlugin::setUp() {
  uri_ = TLSRequestHelper::makeURI(FLAGS_config_tls_endpoint);

  // If the initial configuration includes a non-0 refresh, start an additional
  // service that sleeps and periodically regenerates the configuration.
  if (FLAGS_config_tls_refresh >= 1) {
    Dispatcher::addService(std::make_shared<TLSConfigRefreshRunner>());
  }

  return Status(0, "OK");
}

Status TLSConfigPlugin::genConfig(std::map<std::string, std::string>& config) {
  std::string json;

  auto s = TLSRequestHelper::go<JSONSerializer>(
      uri_, json, FLAGS_config_tls_max_attempts);
  if (!s.ok()) {
    return s;
  }

  if (FLAGS_tls_node_api) {
    // The node API embeds configuration data (JSON escaped).
    pt::ptree tree;
    try {
      std::stringstream input;
      input << json;
      pt::read_json(input, tree);
    } catch (const pt::json_parser::json_parser_error& e) {
      VLOG(1) << "Could not parse JSON from TLS node API";
    }

    // Re-encode the config key into JSON.
    config["tls_plugin"] = unescapeUnicode(tree.get("config", ""));
  } else {
    config["tls_plugin"] = json;
  }
  return s;
}

void TLSConfigRefreshRunner::start() {
  while (true) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    osquery::interruptableSleep(FLAGS_config_tls_refresh * 1000);

    // Access the configuration.
    auto plugin = Registry::get("config", "tls");
    if (plugin != nullptr) {
      auto config_plugin = std::dynamic_pointer_cast<ConfigPlugin>(plugin);

      // The config instance knows the TLS plugin is selected.
      std::map<std::string, std::string> config;
      if (config_plugin->genConfig(config)) {
        Config::getInstance().update(config);
      }
    }
  }
}
}

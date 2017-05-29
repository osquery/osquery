/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/dispatcher.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

#include "osquery/config/plugins/tls.h"

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

/// How long to wait when config update fails
CLI_FLAG(uint64,
         config_tls_accelerated_refresh,
         300,
         "Interval to wait if reading a configuration fails");

DECLARE_bool(tls_secret_always);
DECLARE_string(tls_enroll_override);
DECLARE_bool(tls_node_api);
DECLARE_bool(enroll_always);

REGISTER(TLSConfigPlugin, "config", "tls");

std::atomic<size_t> TLSConfigPlugin::kCurrentDelay{0};

Status TLSConfigPlugin::setUp() {
  if (FLAGS_enroll_always && !FLAGS_disable_enrollment) {
    // clear any cached node key
    clearNodeKey();
    auto node_key = getNodeKey("tls");
    if (node_key.size() == 0) {
      // Could not generate a node key, continue logging to stderr.
      return Status(1, "No node key, TLS config failed.");
    }
  }

  uri_ = TLSRequestHelper::makeURI(FLAGS_config_tls_endpoint);

  kCurrentDelay = FLAGS_config_tls_refresh;

  return Status(0, "OK");
}

void TLSConfigPlugin::updateDelayPeriod(bool success) {
  if (success) {
    if (kCurrentDelay != FLAGS_config_tls_refresh) {
      VLOG(1) << "Normal configuration delay restored";
      kCurrentDelay = FLAGS_config_tls_refresh;
    }
  } else {
    if (kCurrentDelay == FLAGS_config_tls_refresh) {
      VLOG(1) << "Using accelerated configuration delay";
      kCurrentDelay = FLAGS_config_tls_accelerated_refresh;
    }
  }
}

Status TLSConfigPlugin::genConfig(std::map<std::string, std::string>& config) {
  std::string json;

  pt::ptree params;
  if (FLAGS_tls_node_api) {
    // The TLS node API morphs some verbs and variables.
    params.put("_get", true);
  }

  auto s = TLSRequestHelper::go<JSONSerializer>(
      uri_, params, json, FLAGS_config_tls_max_attempts);

  if (s.ok()) {
    if (FLAGS_tls_node_api) {
      // The node API embeds configuration data (JSON escaped).
      pt::ptree tree;
      try {
        std::stringstream input;
        input << json;
        pt::read_json(input, tree);
      } catch (const pt::json_parser::json_parser_error& /* e */) {
        VLOG(1) << "Could not parse JSON from TLS node API";
      }

      // Re-encode the config key into JSON.
      config["tls_plugin"] = unescapeUnicode(tree.get("config", ""));
    } else {
      config["tls_plugin"] = json;
    }
  }
  updateDelayPeriod(s.ok());

  // If the initial configuration includes a non-0 refresh, start an additional
  // service that sleeps and periodically regenerates the configuration.
  if (!started_thread_ && FLAGS_config_tls_refresh >= 1) {
    Dispatcher::addService(std::make_shared<TLSConfigRefreshRunner>());
    started_thread_ = true;
  }
  return s;
}

void TLSConfigRefreshRunner::start() {
  while (!interrupted()) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    pauseMilli(TLSConfigPlugin::kCurrentDelay * 1000);
    // Since the pause occurs before the logic, we need to check for an
    // interruption request.
    if (interrupted()) {
      return;
    }

    // Access the configuration.
    auto plugin = RegistryFactory::get().plugin("config", "tls");
    if (plugin != nullptr) {
      auto config_plugin = std::dynamic_pointer_cast<ConfigPlugin>(plugin);

      // The config instance knows the TLS plugin is selected.
      std::map<std::string, std::string> config;
      if (config_plugin->genConfig(config)) {
        Config::get().update(config);
      }
    }
  }
}
}

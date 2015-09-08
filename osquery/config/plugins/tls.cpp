/*
 *  Copyright (c) 2014, Facebook, Inc.
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

#include <osquery/config.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/dispatcher/dispatcher.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(uint64, config_tls_max_attempts, 3, "Number of times to attempt a request")

/// Config retrieval TLS endpoint (path) using TLS hostname.
CLI_FLAG(string,
         config_tls_endpoint,
         "",
         "TLS/HTTPS endpoint for config retrieval");

/// Config polling/updating, only applies to TLS configurations.
FLAG(uint64,
     config_tls_refresh,
     0,
     "Optional interval in seconds to re-read configuration (min=10)");

DECLARE_bool(tls_secret_always);
DECLARE_string(tls_enroll_override);
DECLARE_bool(tls_node_api);

class TLSConfigPlugin : public ConfigPlugin {
 public:
  Status setUp();
  Status genConfig(std::map<std::string, std::string>& config);

 protected:
  std::string uri_;
};

class TLSConfigRefreshRunner : public InternalRunnable {
 public:
  TLSConfigRefreshRunner() {}

  /// A simple wait/interruptible lock.
  void start();
};

REGISTER(TLSConfigPlugin, "config", "tls");

Status TLSConfigPlugin::setUp() {
  // If the initial configuration includes a non-0 refresh, start an additional
  // service that sleeps and periodically regenerates the configuration.
  if (FLAGS_config_tls_refresh >= 10) {
    Dispatcher::addService(std::make_shared<TLSConfigRefreshRunner>());
  }

  uri_ = TLSRequestHelper::makeURI(FLAGS_config_tls_endpoint);
  return Status(0, "OK");
}

Status TLSConfigPlugin::genConfig(std::map<std::string, std::string>& config) {
  std::string json;

  auto s = TLSRequestHelper::go<JSONSerializer>(
      uri_, json, FLAGS_config_tls_max_attempts);
  if (s.ok()) {
    config["tls_plugin"] = json;
  }
  return s;
}

void TLSConfigRefreshRunner::start() {
  while (true) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    osquery::interruptableSleep(FLAGS_config_tls_refresh * 1000);

    // The config instance knows the TLS plugin is selected.
    Config::getInstance().load();
  }
}
}

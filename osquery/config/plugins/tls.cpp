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

#include "osquery/remote/requests.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/serializers/json.h"

#define CONFIG_TLS_MAX_ATTEMPTS 3

namespace osquery {

/// Config retrieval TLS endpoint (path) using TLS hostname.
FLAG(string,
     config_tls_endpoint,
     "",
     "TLS/HTTPS endpoint for config retrieval");

class TLSConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(std::map<std::string, std::string>& config);
};

REGISTER(TLSConfigPlugin, "config", "tls");

Status getConfig(const std::string& uri, boost::property_tree::ptree& output) {
  // Request the TLS enroll plugin's enrollment secret.
  PluginResponse response;
  Registry::call("enroll", "tls", {{"action", "enroll"}}, response);

  // Enrollment keys are optional, as enrollment may be disabled.
  std::string enroll_key;
  if (response.size() > 0 && response[0].count("enroll_key") != 0) {
    enroll_key = response[0].at("enroll_key");
  }

  // Make a request to the config endpoint, providing the node secret.
  boost::property_tree::ptree params;
  params.put<std::string>("enroll_key", enroll_key);

  auto request = Request<TLSTransport, JSONSerializer>(uri);
  auto status = request.call(params);
  if (!status.ok()) {
    return status;
  }

  // The call succeeded, store the enrolled key.
  status = request.getResponse(output);
  if (!status.ok()) {
    return status;
  }

  // Receive config or key rejection
  if (output.count("enroll_invalid") > 0) {
    return Status(1, "Config retrieval failed: Invalid enrollment key");
  }
  return Status(0, "OK");
}

Status TLSConfigPlugin::genConfig(std::map<std::string, std::string>& config) {
  auto uri = "https://" + FLAGS_tls_hostname + FLAGS_config_tls_endpoint;
  VLOG(1) << "TLSConfigPlugin requesting a config from: " << uri;

  boost::property_tree::ptree recv;
  for (size_t i = 1; i <= CONFIG_TLS_MAX_ATTEMPTS; i++) {
    auto status = getConfig(uri, recv);
    if (status.ok()) {
      std::stringstream ss;
      write_json(ss, recv);
      config["tls_plugin"] = ss.str();
      return Status(0, "OK");
    } else if (i == CONFIG_TLS_MAX_ATTEMPTS) {
      break;
    }

    LOG(WARNING) << "Failed config retrieval from " << uri << " ("
                 << status.what() << ") retrying...";
    ::sleep(i * i);
  }

  return Status(1, "TLSConfigPlugin failed");
}
}

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

#include "osquery/config/plugins/tls_config.h"

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

DECLARE_bool(tls_secret_always);
DECLARE_string(tls_enroll_override);
DECLARE_bool(tls_node_api);
DECLARE_bool(enroll_always);

REGISTER(TLSConfigPlugin, "config", "tls");

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
  return Status(0, "OK");
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

  return s;
}
}

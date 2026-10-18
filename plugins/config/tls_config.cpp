/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/utility.h>
// clang-format on

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/registry/registry.h>
#include <osquery/remote/enroll/enroll.h>
#include <osquery/remote/requests.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/utils/chars.h>
#include <osquery/utils/json/json.h>
#include <plugins/config/tls_config.h>

#include <sstream>
#include <vector>

namespace osquery {

CLI_FLAG(uint64,
         config_tls_max_attempts,
         3,
         "Number of attempts to retry a TLS config request");

/// Config retrieval TLS endpoint (path) using TLS hostname.
CLI_FLAG(string,
         config_tls_endpoint,
         "",
         "TLS/HTTPS endpoint for config retrieval");

CLI_FLAG(bool,
         config_tls_etag,
         true,
         "Send an etag with TLS config requests so the server may respond "
         "with a minimal body when the config is unchanged");

DECLARE_bool(tls_node_api);
DECLARE_bool(enroll_always);

/// The reserved etag value a server uses to signal an unchanged config.
const std::string kEtagNotModified{"ok"};

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
  std::lock_guard<std::mutex> lock(mutex_);

  std::string json;
  JSON params;
  // The node API is a GET request without a body; it cannot carry an etag.
  const bool use_etag = FLAGS_config_tls_etag && !FLAGS_tls_node_api;
  if (FLAGS_tls_node_api) {
    // The TLS node API morphs some verbs and variables.
    params.addCopy("_get", true);
  }

  if (use_etag) {
    // The presence of the field, even empty, requests conditional
    // responses; the value is the last one the server assigned.
    params.addCopy("etag", etag_);
  } else {
    etag_.clear();
    applied_ = false;
  }

  auto s = TLSRequestHelper::go<JSONSerializer>(
      uri_, params, json, FLAGS_config_tls_max_attempts);
  if (!s.ok()) {
    return s;
  }

  if (FLAGS_tls_node_api) {
    // The node API embeds configuration data (JSON escaped).

    JSON tree;
    Status parse_status = tree.fromString(json);
    if (!parse_status.ok()) {
      VLOG(1) << "Could not parse JSON from TLS config node API";
      return Status::failure("Could not parse JSON from TLS config node API");
    }

    if (!tree.doc().IsObject()) {
      return Status::failure(
          "Root of the JSON from TLS config node API is not an object");
    }

    // Re-encode the config key into JSON.
    auto it = tree.doc().FindMember("config");
    config["tls_plugin"] =
        unescapeUnicode(it != tree.doc().MemberEnd() && it->value.IsString()
                            ? it->value.GetString()
                            : "");
    return s;
  }

  if (use_etag) {
    JSON tree;
    if (tree.fromString(json).ok() && tree.doc().IsObject()) {
      auto it = tree.doc().FindMember("etag");
      if (it != tree.doc().MemberEnd() && it->value.IsString()) {
        const std::string etag = it->value.GetString();
        if (etag == kEtagNotModified) {
          if (etag_.empty()) {
            return Status::failure(
                "Server signaled an unchanged config to a request that sent "
                "no etag");
          }
          if (!applied_) {
            const std::string message =
                "Server config is unchanged, but the previous refresh failed "
                "to apply it";
            LOG(WARNING) << message;
            return Status::failure(message);
          }
          return Status(2, "Config unchanged");
        }

        // A new config; acknowledge its etag only once it is applied.
        etag_ = etag;
        applied_ = false;
        tree.doc().RemoveMember("etag");
        return tree.toString(config["tls_plugin"]);
      }
    }

    // The server did not assign an etag; conditional responses are not
    // supported and the response is the config, byte for byte.
    etag_.clear();
    applied_ = false;
  }

  config["tls_plugin"] = json;
  return s;
}

Status TLSConfigPlugin::configApplied() {
  std::lock_guard<std::mutex> lock(mutex_);
  applied_ = true;
  return Status::success();
}
} // namespace osquery

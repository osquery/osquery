/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/utility.h>
// clang-format on

#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/killswitch/plugins/killswitch_tls.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/remote/serializers/json.h>

namespace osquery {

CLI_FLAG(uint64,
         killswitch_tls_max_attempts,
         3,
         "Number of attempts to retry a TLS killswitch config request");

/// Config retrieval TLS endpoint (path) using TLS hostname.
CLI_FLAG(string,
         killswitch_tls_endpoint,
         "",
         "TLS/HTTPS endpoint for killswitch config retrieval");

DECLARE_bool(enroll_always);

REGISTER(TLSKillswitchPlugin, Killswitch::killswitch_, "tls");

Status TLSKillswitchPlugin::setUp() {
  if (FLAGS_enroll_always && !FLAGS_disable_enrollment) {
    // clear any cached node key
    clearNodeKey();
    auto node_key = getNodeKey("tls");
    if (node_key.size() == 0) {
      // Could not generate a node key, continue logging to stderr.
      return Status(1, "No node key, TLS config failed.");
    }
  }

  uri_ = TLSRequestHelper::makeURI(FLAGS_killswitch_tls_endpoint);
  uri_ += ((uri_.find('?') != std::string::npos) ? "&" : "?");
  uri_ += "request=killswitch";

  return KillswitchRefreshablePlugin::setUp();
}

ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError>
TLSKillswitchPlugin::refresh() {
  std::string content;
  JSON params;
  // The TLS node API morphs some verbs and variables.
  params.add("_get", true);

  auto s = TLSRequestHelper::go<JSONSerializer>(
      uri_, params, content, FLAGS_killswitch_tls_max_attempts);
  if (!s.ok()) {
    return createError(
               KillswitchRefreshablePlugin::RefreshError::NoContentReached)
           << "Could not retrieve config file from network";
  }

  JSON tree;
  Status parse_status = tree.fromString(content);
  if (!parse_status.ok()) {
    return createError(KillswitchRefreshablePlugin::RefreshError::ParsingError)
           << "Could not parse JSON from TLS killswitch node API";
  }

  // Extract config map from json
  auto it = tree.doc().FindMember("config");
  if (it == tree.doc().MemberEnd()) {
    return createError(KillswitchRefreshablePlugin::RefreshError::ParsingError)
           << "Killswitch member config is missing";
  }

  if (!it->value.IsString()) {
    return createError(KillswitchRefreshablePlugin::RefreshError::ParsingError)
           << "Killswitch member config is not a string";
  }

  content = it->value.GetString();

  auto result = KillswitchPlugin::parseMapJSON(content);
  if (result) {
    setCache(*result);
    return Success();
  } else {
    return createError(KillswitchRefreshablePlugin::RefreshError::ParsingError)
           << result.getError().getMessage();
  }
}
} // namespace osquery

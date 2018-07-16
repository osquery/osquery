/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/killswitch/plugins/killswitch_tls.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/remote/utility.h>

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

REGISTER(TLSKillswitchPlugin, "killswitch", "tls");

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
  return Status(0, "OK");
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
        KillswitchRefreshablePlugin::RefreshError::NoContentReached,
        "Could not retreive config file from network");
  }

  auto result = KillswitchPlugin::parseMapJSON(content);
  if (result) {
    setCache(*result);
    return Success();
  } else {
    return createError(KillswitchRefreshablePlugin::RefreshError::ParsingError,
                       result.getError().getFullMessageRecursive());
  }
}
} // namespace osquery

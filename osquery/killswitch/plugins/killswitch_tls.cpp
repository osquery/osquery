#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/killswitch/plugins/killswitch_tls.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

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

Expected<std::string, KillswitchJSON::GetJSONError>
TLSKillswitchPlugin::getJSON() {
  std::string json, content;
  JSON params;
  // The TLS node API morphs some verbs and variables.
  params.add("_get", true);

  auto s = TLSRequestHelper::go<JSONSerializer>(
      uri_, params, content, FLAGS_killswitch_tls_max_attempts);
  if (s.ok()) {
    return content;
  } else {
    return createError(KillswitchJSON::GetJSONError::NetworkFailure,
                       "Could not retreive config file from network");
  }
}
} // namespace osquery

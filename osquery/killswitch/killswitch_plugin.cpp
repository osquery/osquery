#include <string>

#include <chrono>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/registry_factory.h>

namespace osquery {

CREATE_REGISTRY(KillswitchPlugin, "killswitch");

Status KillswitchPlugin::call(const PluginRequest& request,
                              PluginResponse& response) {
  auto action = request.find("action");
  if (action == request.end()) {
    return Status(1, "Config plugins require an action");
  }
  if (action->second == "isEnabled") {
    auto key = request.find("key");
    if (key == request.end()) {
      return Status(1, "isEnabled action requires key");
    }

    bool enabled = 0;
    auto status = isEnabled(key->second, enabled);
    if (status.ok()) {
      response.push_back({{"isEnabled", enabled ? "true" : "false"}});
    }
    return status;
  }
  return Status(1, "Could not find appropirate action mapping");
}

void KillswitchPlugin::clearCache() {
  killswitchMap.clear();
}

Status KillswitchPlugin::addCacheEntry(const std::string& key, bool value) {
  killswitchMap[key] = value;
  return Status();
}

Status KillswitchPlugin::isEnabled(const std::string& key, bool& isEnabled) {
  if (killswitchMap.count(key)) {
    isEnabled = killswitchMap[key];
    return Status();
  } else {
    isEnabled = false;
    return Status(1, "Could not find key " + key);
  }
}

} // namespace osquery

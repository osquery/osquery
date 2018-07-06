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
    return Status(1, "Killswitch plugins require an action");
  }
  if (action->second == "isEnabled") {
    auto key = request.find("key");
    if (key == request.end()) {
      return Status(1, "isEnabled action requires key");
    }

    auto result = isEnabled(key->second);

    if (result) {
      response.push_back({{"isEnabled", *result ? "true" : "false"}});
      return Status::success();
    } else {
      return Status::failure(result.getError().getFullMessageRecursive());
    }
  }
  return Status(1, "Could not find appropirate action mapping");
}

void KillswitchPlugin::clearCache() {
  WriteLock wlock(lock_);
  killswitchMap_.clear();
}

void KillswitchPlugin::addCacheEntry(const std::string& key, bool value) {
  WriteLock wlock(lock_);
  killswitchMap_[key] = value;
}

Expected<bool, KillswitchPlugin::IsEnabledError> KillswitchPlugin::isEnabled(
    const std::string& key) {
  ReadLock rlock(lock_);
  if (killswitchMap_.find(key) != killswitchMap_.end()) {
    return killswitchMap_[key];
  } else {
    return createError(KillswitchPlugin::IsEnabledError::NoKeyFound,
                       "Could not find key ")
           << key;
  }
}

} // namespace osquery

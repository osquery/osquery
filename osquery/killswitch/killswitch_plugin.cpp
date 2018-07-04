#include <string>

#include <chrono>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

CREATE_REGISTRY(KillswitchPlugin, "killswitch");

FLAG(uint32,
     killswitch_refresh_rate,
     10,
     "Refresh rate of killswitch in seconds");

class KillswitchRefresher : public InternalRunnable {
 public:
  KillswitchRefresher(size_t update_interval)
      : InternalRunnable("KillswitchRefreshRunner"),
        update_interval_(update_interval) {}
  /// A simple wait/interruptible lock.
  void start() override {
    while (!interrupted()) {
      osquery::Killswitch::get().refresh();
      pauseMilli(
          std::chrono::milliseconds(std::chrono::seconds(update_interval_)));
    }
  }

 private:
  const size_t update_interval_;
};

Status KillswitchPlugin::call(const PluginRequest& request,
                              PluginResponse& response) {
  auto action = request.find("action");
  if (action == request.end()) {
    return Status(1, "Config plugins require an action");
  }

  if (action->second == "refresh") {
    return refresh();
  } else if (action->second == "isEnabled") {
    auto key = request.find("key");
    if (key == request.end()) {
      return Status(1, "isEnabled action requires key");
    }

    bool enabled = 0;
    auto status = isEnabled(key->second, enabled);
    response.push_back({{"isEnabled", enabled ? "true" : "false"}});
    return status;
  }
  return Status(1, "Could not find appropirate action mapping");
}

Status KillswitchPlugin::setUp() {
  if (FLAGS_killswitch_refresh_rate > 0) {
    Dispatcher::addService(
        std::make_shared<KillswitchRefresher>(FLAGS_killswitch_refresh_rate));
  }
  return Status::success();
}

void KillswitchPlugin::clearCache() {
  killswitchMap.clear();
}
Status KillswitchPlugin::addCacheEntry(const std::string& key, bool value) {
  if (killswitchMap.find(key) == killswitchMap.end()) {
    return Status::failure(1, "Key already exists");
  }
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

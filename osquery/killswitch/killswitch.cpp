#include <string>

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

FLAG(int32,
     killswitch_refresh_rate,
     10,
     "Refresh rate of killswitch in seconds");
FLAG(bool, enable_killswitch, true, "Enable killswitch plugin");
FLAG(string, killswitch_plugin, "killswitch_test", "Killswitch plugin name.");

namespace killswitch {
Status isTestSwitchOn(bool& isEnabled) {
  if (!FLAGS_enable_killswitch) {
    return Status(1);
  }

  PluginResponse response;
  auto status =
      Registry::call("killswitch",
                     FLAGS_killswitch_plugin,
                     {{"action", "isEnabled"}, {"key", "testSwitch"},},
                      response);

}
} // namespace killswitch

CREATE_REGISTRY(KillswitchPlugin, "killswitch");

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

} // namespace osquery

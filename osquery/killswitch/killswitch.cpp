#include <string>

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {
FLAG(bool, enable_killswitch, true, "Enable killswitch plugin");
FLAG(string, killswitch_plugin, "killswitch_test", "Killswitch plugin name.");

CREATE_REGISTRY(KillswitchPlugin, "killswitch");

Status KillswitchPlugin::call(const PluginRequest& request, PluginResponse& response){
  auto action = request.find("action");
  if (action == request.end()) {
    return Status(1, "Config plugins require an action");
  }

  if(action->second == "refresh"){
    return refresh();
  }

}

} // namespace osquery

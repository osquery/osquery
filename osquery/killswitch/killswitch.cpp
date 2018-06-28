#include <string>

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {
FLAG(bool, enable_killswitch, true, "Enable killswitch plugin");
FLAG(string, killswitch_plugin, "killswitch_test", "Killswitch plugin name.");

CREATE_REGISTRY(KillswitchPlugin, "killswitch");

bool KillswitchPlugin::isEnabled(std::string switchKey) {
  return true;
}

} // namespace osquery

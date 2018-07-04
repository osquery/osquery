#include <string>

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

FLAG(bool, enable_killswitch, true, "Enable killswitch plugin");
FLAG(string,
     killswitch_plugin,
     "killswitch_filesystem",
     "Killswitch plugin name.");

Expected<bool, SwitchOnError> Killswitch::isSwitchOn(const std::string& key, bool& isEnabled) {
  PluginResponse response;
  auto status = Registry::call("killswitch",
                               FLAGS_killswitch_plugin,
                               {
                                   {"action", "isEnabled"}, {"key", key},
                               },
                               response);
  if (!status.ok()) {
    return status;
  }
  if (response.size() != 1) {
    return Status::failure("Response size should be 1 but is " +
                           std::to_string(response.size()));
  }
  const auto& responseMap = response[0];
  const auto& isEnabledItem = responseMap.find("isEnabled");
  if (isEnabledItem == responseMap.end()) {
    return Status::failure(
        "isEnabled key missing in reponse of the action: isEnabled");
  }

  const auto& isEnabledValue = isEnabledItem->second;
  if (isEnabledValue == "True") {
    isEnabled = true;
    return Status::success();
  } else if (isEnabledValue == "False") {
    isEnabled = false;
    return Status::success();
  } else {
    return Status::failure("Unknown isEnabled value " + isEnabledValue);
  }
}

Status Killswitch::refresh() {
  PluginResponse response;
  auto status = Registry::call(
      "killswitch", FLAGS_killswitch_plugin, {{"action", "refresh"}}, response);
  return status;
}

Expected<bool, SwitchOnError> Killswitch::isTestSwitchOn() {
  return isSwitchOn("testSwitch");
}

} // namespace osquery

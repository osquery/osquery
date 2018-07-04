#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/registry_factory.h>
#include <string>

namespace osquery {

FLAG(bool, enable_killswitch, true, "Enable killswitch plugin");
FLAG(string,
     killswitch_plugin,
     "killswitch_filesystem",
     "Killswitch plugin name.");

Killswitch::Killswitch() {}
Killswitch::~Killswitch() = default;

Expected<bool, SwitchOnError> Killswitch::isSwitchOn(const std::string& key) {
  PluginResponse response;
  auto status = Registry::call("killswitch",
                               {
                                   {"action", "isEnabled"},
                                   {"key", key},
                               },
                               response);
  if (!status.ok()) {
    return Error<SwitchOnError>(SwitchOnError::CallFailed, status.getMessage());
  }

  if (response.size() != 1) {
    return Error<SwitchOnError>(
        SwitchOnError::IncorrectResponseFormat,
        "Response size should be 1 but is " + std::to_string(response.size()));
  }
  const auto& responseMap = response[0];
  const auto& isEnabledItem = responseMap.find("isEnabled");
  if (isEnabledItem == responseMap.end()) {
    return Error<SwitchOnError>(
        SwitchOnError::IncorrectResponseFormat,
        "isEnabled key missing in reponse of the action: isEnabled");
  }

  const auto& isEnabledValue = isEnabledItem->second;
  if (isEnabledValue == "true") {
    return true;
  } else if (isEnabledValue == "false") {
    return false;
  } else {
    return Error<SwitchOnError>(SwitchOnError::IncorrectValue,
                                "Unknown isEnabled value " + isEnabledValue);
  }
}

Status Killswitch::refresh() {
  PluginResponse response;
  auto status = Registry::call("killswitch", {{"action", "refresh"}}, response);
  return status;
}

Expected<bool, SwitchOnError> Killswitch::isTestSwitchOn() {
  return isSwitchOn("testSwitch");
}
Expected<bool, SwitchOnError> Killswitch::isTest2SwitchOn() {
  return isSwitchOn("test2Switch");
}

} // namespace osquery

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
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

// bool Killswitch::isMyTutorialSwitchEnabled();{
//   return isEnabled("tutorialSwitch", true);
// }

bool Killswitch::isEnabled(const std::string& key, bool isEnabledDefault) {
  auto result = isEnabled(key);
  if (result) {
    return *result;
  } else {
    VLOG(1) << result.getError().getFullMessageRecursive();
    return isEnabledDefault;
  }
}

Expected<bool, Killswitch::SwitchOnError> Killswitch::isEnabled(
    const std::string& key) {
  PluginResponse response;
  auto status = Registry::call(
      "killswitch", {{"action", "isEnabled"}, {"key", key}}, response);
  if (!status.ok()) {
    return createError(Killswitch::SwitchOnError::CallFailed,
                       status.getMessage());
  }

  if (response.size() != 1) {
    return createError(Killswitch::SwitchOnError::IncorrectResponseFormat,
                       "Response size should be 1 but is ")
           << std::to_string(response.size());
  }
  const auto& responseMap = response[0];
  const auto& isEnabledItem = responseMap.find("isEnabled");
  if (isEnabledItem == responseMap.end()) {
    return createError(
        Killswitch::SwitchOnError::IncorrectResponseFormat,
        "isEnabled key missing in reponse of the action: isEnabled");
  }

  const auto& isEnabledValue = isEnabledItem->second;
  if (isEnabledValue == "1") {
    return true;
  } else if (isEnabledValue == "0") {
    return false;
  } else {
    return createError(Killswitch::SwitchOnError::IncorrectValue,
                       "Unknown isEnabled value " + isEnabledValue);
  }
}

Status Killswitch::refresh() {
  PluginResponse response;
  auto status = Registry::call("killswitch", {{"action", "refresh"}}, response);
  return status;
}

} // namespace osquery

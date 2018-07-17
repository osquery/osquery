/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

const char Killswitch::killswitch_[] = "killswitch";
const char Killswitch::action_[] = "action";
const char Killswitch::isEnabled_[] = "isEnabled";
const char Killswitch::key_[] = "key";
const char Killswitch::refresh_[] = "refresh";

FLAG(bool, enable_killswitch, false, "Enable killswitch plugin");
FLAG(string,
     killswitch_plugin,
     "killswitch_filesystem",
     "Killswitch plugin name.");

Killswitch::Killswitch() {}
Killswitch::~Killswitch() = default;

// bool Killswitch::isMyTutorialFeatureEnabled();{
//   return isNewCodeEnabled("tutorialSwitch");
// }

bool Killswitch::isNewCodeEnabled(const std::string& key) {
  auto result = isEnabled(key);
  if (result) {
    return *result;
  } else {
    VLOG(1) << result.getError().getFullMessageRecursive();
    return true;
  }
}

Expected<bool, Killswitch::IsEnabledError> Killswitch::isEnabled(
    const std::string& key) {
  PluginResponse response;
  auto status = Registry::call(
      Killswitch::killswitch_,
      {{Killswitch::action_, Killswitch::isEnabled_}, {Killswitch::key_, key}},
      response);
  if (!status.ok()) {
    return createError(Killswitch::IsEnabledError::CallFailed,
                       status.getMessage());
  }

  if (response.size() != 1) {
    return createError(Killswitch::IsEnabledError::IncorrectResponseFormat,
                       "Response size should be 1 but is ")
           << std::to_string(response.size());
  }
  const auto& response_map = response[0];
  const auto& is_enabled_item = response_map.find(Killswitch::isEnabled_);
  if (is_enabled_item == response_map.end()) {
    return createError(
        Killswitch::IsEnabledError::IncorrectResponseFormat,
        "isEnabled key missing in response of the action: isEnabled");
  }

  const auto& is_enabled_value = is_enabled_item->second;
  if (is_enabled_value == "1") {
    return true;
  } else if (is_enabled_value == "0") {
    return false;
  } else {
    return createError(Killswitch::IsEnabledError::IncorrectValue,
                       "Unknown isEnabled value " + is_enabled_value);
  }
}

Status Killswitch::refresh() {
  PluginResponse response;
  auto status = Registry::call(Killswitch::killswitch_,
                               {{Killswitch::action_, Killswitch::refresh_}},
                               response);
  return status;
}

} // namespace osquery

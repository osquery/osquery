#include <string>

#include <osquery/killswitch/killswitch_plugin.h>

#include "osquery/core/json.h"
#include "osquery/killswitch/plugins/killswitch_json.h"

namespace osquery {

ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError>
KillswitchJSON::refresh() {
  auto content = getJSON();
  if (!content) {
    return createError(KillswitchRefreshablePlugin::RefreshError::NoContent,
                       "Could not get content from the source");
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(*content) || !doc.doc().IsObject()) {
    return createError(
        KillswitchRefreshablePlugin::RefreshError::ParsingError,
        "Error parsing the killswitch JSON. Content : " + *content);
  }
  clearCache();

  for (const auto& keyValue : doc.doc().GetObject()) {
    if (!keyValue.name.IsString()) {
      return createError(
          KillswitchRefreshablePlugin::RefreshError::IncorrectKeyType,
          "Killswitch config key was not string");
    }
    auto key = keyValue.name.GetString();
    if (!keyValue.value.IsBool()) {
      return createError(
          KillswitchRefreshablePlugin::RefreshError::IncorrectValueType,
          std::string("At Killswitch config key: ") + key +
              "value was not bool");
    }
    bool value = keyValue.value.GetBool();
    addCacheEntry(key, value);
  }
  return Success();
}

} // namespace osquery

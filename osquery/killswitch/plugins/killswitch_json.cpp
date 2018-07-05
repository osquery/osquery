#include <string>

#include <osquery/killswitch/killswitch_plugin.h>

#include "osquery/core/json.h"
#include "osquery/killswitch/plugins/killswitch_json.h"

namespace osquery {

Status KillswitchJSON::refresh() {
  std::string content;

  auto status = getJSON(content);
  if (!status.ok()) {
    return status;
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(content) || !doc.doc().IsObject()) {
    return Status(1, "Error parsing the config JSON. Content : " + content);
  }
  clearCache();

  for (auto& m : doc.doc().GetObject()) {
    if (!m.name.IsString()) {
      return Status::failure(1, "Killswitch config key was not string");
    }
    std::string key = m.name.GetString();
    if (!m.value.IsBool()) {
      return Status::failure(
          1, "At Killswitch config key: " + key + "value was not bool");
    }
    bool value = m.value.GetBool();
    status = addCacheEntry(key, value);
    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
    }
  }

  return Status();
}

} // namespace osquery

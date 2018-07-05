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
    return Status(1, "Error parsing the killswitch JSON. Content : " + content);
  }
  clearCache();

  for (const auto& keyValue : doc.doc().GetObject()) {
    if (!keyValue.name.IsString()) {
      return Status::failure("Killswitch config key was not string");
    }
    auto key = keyValue.name.GetString();
    if (!keyValue.value.IsBool()) {
      return Status::failure(std::string("At Killswitch config key: ") + key + "value was not bool");
    }
    bool value = keyValue.value.GetBool();
    status = addCacheEntry(key, value);
    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
    }
  }

  return Status::success();
}

} // namespace osquery

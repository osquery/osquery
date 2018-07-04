#include <string>

#include <boost/filesystem/operations.hpp>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/json.h"
#include "osquery/killswitch/plugins/killswitch_filesystem.h"
namespace errc = boost::system::errc;
namespace fs = boost::filesystem;

namespace osquery {
FLAG(string,
     killswitch_config_path,
     (fs::path(OSQUERY_HOME) / "killswitch.conf").make_preferred().string(),
     "Path to JSON killswitch config file");

KillswitchFilesystem::KillswitchFilesystem(const std::string& conf_path)
    : conf_path_(conf_path) {}
KillswitchFilesystem::KillswitchFilesystem()
    : KillswitchFilesystem(FLAGS_killswitch_config_path) {}

Status KillswitchFilesystem::refresh() {
  std::string content;
  boost::system::error_code ec;
  if (!fs::is_regular_file(conf_path_, ec) || ec.value() != errc::success ||
      !readFile(conf_path_, content).ok()) {
    return Status(1, "config file does not exist: " + conf_path_);
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
    auto status = addCacheEntry(key, value);
    if (!status.ok()) {
      LOG(WARNING) << status.getMessage();
    }
  }

  return Status();
}

REGISTER(KillswitchFilesystem, "killswitch", "killswitch_filesystem");

} // namespace osquery

#include <iostream>
#include <string>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/json.h"
#include "osquery/killswitch/plugins/killswitch_filesystem.h"
#include <string>

#include <chrono>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
namespace errc = boost::system::errc;
namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
FLAG(string,
         killswitch_config_path,
         (fs::path(OSQUERY_HOME) / "killswitch.conf").make_preferred().string(),
         "Path to JSON killswitch config file");
         FLAG(uint32,
              x,
              10,
              "Refresh rate of killswitch in seconds");
Status KillswitchFilesystem::refresh() {
  std::string content;
  boost::system::error_code ec;
  if (!fs::is_regular_file(FLAGS_killswitch_config_path, ec) ||
      ec.value() != errc::success ||
      !readFile(FLAGS_killswitch_config_path, content).ok()) {
    return Status(
        1, "config file does not exist: " + FLAGS_killswitch_config_path);
  }

  auto doc = JSON::newObject();
  if (!doc.fromString(content) || !doc.doc().IsObject()) {
    return Status(1, "Error parsing the config JSON");
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
      // TODO
    }
  }

  return Status();
}

REGISTER(KillswitchFilesystem, "killswitch", "killswitch_filesystem");

} // namespace osquery

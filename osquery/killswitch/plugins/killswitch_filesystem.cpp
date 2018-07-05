#include <string>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

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

KillswitchFilesystem::KillswitchFilesystem(
    const boost::filesystem::path& conf_path)
    : conf_path_(conf_path) {}
KillswitchFilesystem::KillswitchFilesystem()
    : KillswitchFilesystem(FLAGS_killswitch_config_path) {}

Status KillswitchFilesystem::getJSON(std::string& content) {
  boost::system::error_code ec;
  if (!fs::is_regular_file(conf_path_, ec) || ec.value() != errc::success ||
      !readFile(conf_path_, content).ok()) {
    return Status::failure("config file does not exist: " +
                           conf_path_.string());
  }

  return Status::success();
}

REGISTER(KillswitchFilesystem, "killswitch", "killswitch_filesystem");

} // namespace osquery

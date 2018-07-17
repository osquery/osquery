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

#include <boost/filesystem/operations.hpp>

#include <osquery/core/json.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/killswitch/plugins/killswitch_filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

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

ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError>
KillswitchFilesystem::refresh() {
  std::string content;
  boost::system::error_code ec;
  if (!fs::is_regular_file(conf_path_, ec) || ec.value() != errc::success ||
      !readFile(conf_path_, content).ok()) {
    createError(KillswitchRefreshablePlugin::RefreshError::NoContentReached,
                "config file does not exist: " + conf_path_.string());
  }

  auto result = KillswitchPlugin::parseMapJSON(content);
  if (result) {
    setCache(*result);
    return Success();
  } else {
    return createError(KillswitchRefreshablePlugin::RefreshError::ParsingError,
                       result.getError().getFullMessageRecursive());
  }
}

REGISTER(KillswitchFilesystem,
         Killswitch::killswitch_str,
         "killswitch_filesystem");

} // namespace osquery

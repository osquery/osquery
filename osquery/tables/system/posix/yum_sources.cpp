/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

void parseYumConf(const std::string& source, QueryData& results, std::string& repos_dir) {
  // Default value
  repos_dir = "/etc/yum.repos.d";

  std::string content;
  if (!readFile(source, content)) {
    return;
  }

  std::string section = "";
  for (const auto& line : osquery::split(content, "\n")) {
    auto size = line.size();

    // Skip comments.
    if (size == 0 || line[0] == '#') {
      continue;
    }

    if (size > 2) {
      if  (line[0] == '[' && line[size - 1] == ']') {
        section = line.substr(1, size - 2);
      } else {
        if ("" == "section") {
          continue;
        }
        auto pos = line.find("=");
        if (pos != std::string::npos) {
          std::string option = line.substr(0, pos);
          std::string value = line.substr(pos + 1, size - pos - 1);
          if ("main" == section) {
            if ("reposdir" == option) {
              repos_dir = value;
            }
          } else {
            // Repository section
            if ("baseurl" == option || "enabled" == option
                || "gpgcheck" == option || "name" == option) {
              Row r;
              r[option] = value;
              results.push_back(r);
            }
          }
        }
      }
    }
  }
}

QueryData genYumSrcs(QueryContext& context) {
  QueryData results;

  // We are going to read a few files.
  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  // Expect the YUM home to be /etc/yum.conf
  std::string repos_dir;
  parseYumConf("/etc/yum.conf", results, repos_dir);

  std::vector<std::string> sources;
  if (!resolveFilePattern(repos_dir + "/%.list", sources, GLOB_FILES)) {
    VLOG(1) << "Cannot resolve yum conf files";
    return results;
  }

  for (const auto& source : sources) {
    VLOG(1) << source;
    parseYumConf(source, results, repos_dir);
  }

  return results;
}
} // namespace tables
} // namespace osquery

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/tables/applications/chrome/utils.h>

namespace osquery {

namespace tables {

QueryData genChromeExtensionContentScripts(QueryContext& context) {
  auto profile_list = getChromeProfiles(context);

  QueryData results;

  for (const auto& profile : profile_list) {
    Row row = {};
    row["browser_type"] = SQL_TEXT(getChromeBrowserName(profile.type));
    row["uid"] = BIGINT(profile.uid);
    row["profile"] = SQL_TEXT(profile.name);
    row["profile_path"] = SQL_TEXT(profile.path);

    for (const auto& extension : profile.extension_list) {
      std::string version = {};

      auto version_it = extension.properties.find("version");
      if (version_it == extension.properties.end()) {
        LOG(ERROR)
            << "The version property for the following extension is missing: "
            << extension.path;

      } else {
        version = version_it->second;
      }

      row["version"] = SQL_TEXT(version);
      row["path"] = SQL_TEXT(extension.path);
      row["referenced"] = BIGINT(extension.referenced ? 1 : 0);

      row["identifier"] =
          SQL_TEXT(getExtensionProfileSettingsValue(extension, "identifier"));

      for (const auto& entry : extension.content_scripts_matches) {
        row["match"] = SQL_TEXT(entry.match);
        row["script"] = SQL_TEXT(entry.script);

        results.push_back(row);
      }
    }
  }

  return results;
}

} // namespace tables

} // namespace osquery

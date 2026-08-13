/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/applications/chrome/utils.h>

namespace osquery {

namespace tables {

QueryData genChromeSearchEngines(QueryContext& context) {
  auto profile_list = getChromeProfiles(context);

  QueryData results;

  for (const auto& profile : profile_list) {
    // Skip profiles that have no default search provider data at all;
    // there is nothing meaningful to report for them
    if (!profile.search_engine_name.has_value() &&
        !profile.search_engine_keyword.has_value() &&
        !profile.search_engine_url.has_value()) {
      continue;
    }

    Row row = {};
    row["browser_type"] = SQL_TEXT(getChromeBrowserName(profile.type));

    row["uid"] = BIGINT(profile.uid);
    row["profile"] = SQL_TEXT(profile.name);
    row["profile_path"] = SQL_TEXT(profile.path);

    row["name"] = SQL_TEXT(profile.search_engine_name.value_or(""));
    row["keyword"] = SQL_TEXT(profile.search_engine_keyword.value_or(""));
    row["url"] = SQL_TEXT(profile.search_engine_url.value_or(""));

    results.push_back(std::move(row));
  }

  return results;
}

} // namespace tables

} // namespace osquery

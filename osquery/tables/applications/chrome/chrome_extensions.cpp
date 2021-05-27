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
#include <osquery/utils/conversions/tryto.h>

#include <boost/algorithm/string/predicate.hpp>

namespace osquery {

namespace tables {

QueryData genChromeExtensions(QueryContext& context) {
  auto profile_list = getChromeProfiles(context);

  QueryData results;

  for (const auto& profile : profile_list) {
    for (const auto& extension : profile.extension_list) {
      Row row = {};
      row["browser_type"] = SQL_TEXT(getChromeBrowserName(profile.type));

      row["uid"] = BIGINT(profile.uid);
      row["profile"] = SQL_TEXT(profile.name);
      row["profile_path"] = SQL_TEXT(profile.path);

      row["name"] = SQL_TEXT(getExtensionProperty(extension, "name", false));
      row["version"] =
          SQL_TEXT(getExtensionProperty(extension, "version", false));

      row["author"] = SQL_TEXT(getExtensionProperty(extension, "author", true));
      row["manifest_json"] = SQL_TEXT(extension.manifest_json);

      row["update_url"] =
          SQL_TEXT(getExtensionProperty(extension, "update_url", true));

      row["default_locale"] =
          SQL_TEXT(getExtensionProperty(extension, "default_locale", true));

      row["current_locale"] =
          SQL_TEXT(getExtensionProperty(extension, "current_locale", true));

      row["permissions"] =
          SQL_TEXT(getExtensionProperty(extension, "permissions", true));

      row["permissions_json"] = SQL_TEXT(
          getExtensionProperty(extension, "permissions_json", true, "{}"));

      row["optional_permissions"] = SQL_TEXT(
          getExtensionProperty(extension, "optional_permissions", true));

      row["optional_permissions_json"] = SQL_TEXT(getExtensionProperty(
          extension, "optional_permissions_json", true, "{}"));

      auto persistent = getExtensionProperty(extension, "persistent", true);
      row["persistent"] = BIGINT(boost::iequals(persistent, "true") ? 1 : 0);

      row["description"] =
          SQL_TEXT(getExtensionProperty(extension, "description", true));

      row["path"] = SQL_TEXT(extension.path);
      row["manifest_hash"] = SQL_TEXT(extension.manifest_hash);
      row["referenced"] = BIGINT(extension.referenced ? 1 : 0);

      row["state"] =
          SQL_TEXT(getExtensionProfileSettingsValue(extension, "state"));

      row["from_webstore"] = SQL_TEXT(
          getExtensionProfileSettingsValue(extension, "from_webstore"));

      row["install_time"] =
          SQL_TEXT(getExtensionProfileSettingsValue(extension, "install_time"));

      auto converted_timestamp_exp =
          webkitTimeToUnixTimestamp(row.at("install_time"));

      // Make sure install_timestamp is always present, otherwise the
      // integration test will fail the validation
      std::int64_t converted_timestamp{0};
      if (!converted_timestamp_exp.isError()) {
        converted_timestamp = converted_timestamp_exp.take();
      }

      row["install_timestamp"] = BIGINT(converted_timestamp);

      row["referenced_identifier"] = SQL_TEXT(
          getExtensionProfileSettingsValue(extension, "referenced_identifier"));

      if (extension.opt_computed_identifier.has_value()) {
        const auto& computed_identifier = *extension.opt_computed_identifier;
        row["identifier"] = SQL_TEXT(computed_identifier);
      } else {
        row["identifier"] = SQL_TEXT("");
      }

      // This column has been deprecated and is marked as hidden. It will
      // be removed in a future version
      row["locale"] = row["default_locale"];

      results.push_back(std::move(row));
    }
  }

  return results;
}

} // namespace tables

} // namespace osquery

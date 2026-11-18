/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/errno.h>

#include <filesystem>
#include <shlobj_core.h>

namespace osquery {
namespace tables {

void genRecentFilesForUser(QueryData& results,
                           const std::string& user_path_prefix,
                           const std::int64_t& uid) {
  SQL sql(
      "SELECT filename, path, mtime, shortcut_target_path, "
      "shortcut_target_type FROM file WHERE shortcut_target_type != 'File "
      "folder' AND path LIKE '" +
      user_path_prefix +
      "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\%.lnk' ORDER BY mtime "
      "DESC");
  if (!sql.ok()) {
    LOG(ERROR) << "Failed to list recent files: "
               << sql.getStatus().getMessage();
    return;
  }

  for (const auto& row : sql.rows()) {
    if (row.at("shortcut_target_path").empty()) {
      // There are a number of .lnk files in the recent directory that are not
      // displayed in the start menu or explorer. These seem to all not have a
      // target path.
      continue;
    }

    Row r;
    r["uid"] = BIGINT(uid);
    r["filename"] = std::filesystem::path(row.at("shortcut_target_path"))
                        .filename()
                        .string();
    r["path"] = row.at("shortcut_target_path");
    r["mtime"] = row.at("mtime");
    r["type"] = row.at("shortcut_target_type");
    r["shortcut_path"] = row.at("path");
    results.push_back(r);
  }
}

QueryData genRecentFiles(QueryContext& context) {
  QueryData results;

  auto users = usersFromContext(context);
  for (const auto& user : users) {
    if (user.count("uid") == 0 || user.count("directory") == 0) {
      continue;
    }

    const auto& uid_as_string = user.at("uid");
    auto uid_as_big_int = tryTo<int64_t>(uid_as_string, 10);
    if (uid_as_big_int.isError()) {
      LOG(ERROR) << "Invalid uid field returned: " << uid_as_string;
      continue;
    }
    const auto& user_path_prefix = user.at("directory");

    genRecentFilesForUser(results, user_path_prefix, uid_as_big_int.get());
  }

  return results;
}
} // namespace tables
} // namespace osquery
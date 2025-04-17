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
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/errno.h>

#include <filesystem>
#include <shlobj_core.h>

namespace osquery {
namespace tables {

QueryData genWindowsRecentFiles(QueryContext& context) {
  QueryData results;

  PWSTR recentPath = nullptr;
  if (!SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Recent, 0, NULL, &recentPath))) {
    LOG(ERROR) << "Could not get known folder path for recent items: "
               << platformStrerr(GetLastError());
    return results;
  }
  auto path_guard =
      scope_guard::create([&recentPath]() { CoTaskMemFree(recentPath); });

  SQL sql(
      "SELECT filename, path, mtime, shortcut_target_path, "
      "shortcut_target_type FROM file WHERE shortcut_target_type != 'File "
      "folder' AND path LIKE '" +
      wstringToString(std::wstring(recentPath)) +
      "\\%.lnk' ORDER BY mtime DESC");
  if (!sql.ok()) {
    LOG(ERROR) << "Failed to list recent files: "
               << sql.getStatus().getMessage();
    return results;
  }

  for (const auto& row : sql.rows()) {
    if (row.at("shortcut_target_path").empty()) {
      // There are a number of .lnk files in the recent directory that are not
      // displayed in the start menu or explorer. These seem to all not have a
      // target path.
      continue;
    }

    Row r;
    r["filename"] =
        std::filesystem::path(row.at("shortcut_target_path")).filename().string();
    r["path"] = row.at("shortcut_target_path");
    r["mtime"] = row.at("mtime");
    r["type"] = row.at("shortcut_target_type");
    r["shortcut_path"] = row.at("path");
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
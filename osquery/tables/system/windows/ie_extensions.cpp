/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kIEBrowserHelperKeys = {
    "HKEY_LOCAL_"
    "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser "
    "Helper Objects",
    "HKEY_LOCAL_"
    "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explor"
    "er\\Browser "
    "Helper Objects",
    "HKEY_USERS\\%"
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser "
    "Helper Objects",
    "HKEY_USERS\\%"
    "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explor"
    "er\\Browser Helper Objects",
    "HKEY_USERS\\%\\SOFTWARE\\Microsoft\\Internet Explorer\\URLSearchHooks",
};

static inline Status getBHOs(QueryData& results) {
  QueryData regQueryResults;
  auto ret = queryMultipleRegistryKeys(kIEBrowserHelperKeys, regQueryResults);
  if (!ret.ok()) {
    return ret;
  }

  for (const auto& res : regQueryResults) {
    std::vector<std::string> executables;
    auto ret = getClassExecutables(res.at("name"), executables);
    if (!ret.ok()) {
      LOG(WARNING) << "Failed to get class executables: " + ret.getMessage();
      continue;
    }

    std::string clsName;
    ret = getClassName(res.at("name"), clsName);
    if (!ret.ok()) {
      LOG(WARNING) << "Failed to lookup class name: " + ret.getMessage();
      continue;
    }

    for (const auto& exec : executables) {
      Row r;
      r["name"] = std::move(clsName);

      std::string fullPath;
      ret = windowsShortPathToLongPath(exec, fullPath);
      if (ret.ok()) {
        r["path"] = std::move(fullPath);
      }

      std::string productVersion, fileVersion;
      ret = windowsGetVersionInfo(exec, productVersion, fileVersion);
      if (ret.ok()) {
        r["version"] = std::move(productVersion);
      }

      r["registry_path"] = res.at("path");
      results.push_back(r);
    }
  }
  return Status::success();
}
QueryData genIEExtensions(QueryContext& context) {
  QueryData results;
  auto ret = getBHOs(results);
  if (!ret.ok()) {
    LOG(WARNING) << "Error getting browser helper objects";
  }
  return results;
}
} // namespace tables
} // namespace osquery

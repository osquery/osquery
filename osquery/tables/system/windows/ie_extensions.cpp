/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/windows/registry.h"

#define DECLARE_TABLE_IMPLEMENTATION_ie_extensions
#include <generated/tables/tbl_ie_extensions_defs.hpp>

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
  auto ret =
      queryMultipleRegistryKeys(kIEBrowserHelperKeys, "", regQueryResults);

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

      std::string version;
      ret = windowsGetFileVersion(exec, version);
      if (ret.ok()) {
        r["version"] = std::move(version);
      }

      r["registry_path"] = res.at("path");
      results.push_back(r);
    }
  }
  return Status();
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

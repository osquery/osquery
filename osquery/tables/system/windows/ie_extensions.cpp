/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
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
  SQL sql("SELECT name,path FROM registry WHERE key LIKE '" +
          boost::join(kIEBrowserHelperKeys, "' OR key LIKE '") + "'");
  if (!sql.ok()) {
    return sql.getStatus();
  }
  for (const auto& cls : sql.rows()) {
    std::vector<std::string> executables;
    auto ret = getClassExecutables(cls.at("name"), executables);
    if (!ret.ok()) {
      LOG(WARNING) << "Failed to get class executables: " + ret.getMessage();
      continue;
    }

    std::string clsName;
    ret = getClassName(cls.at("name"), clsName);
    if (!ret.ok()) {
      LOG(WARNING) << "Failed to get class name: " + ret.getMessage();
      return ret;
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

      r["registry_path"] = cls.at("path");
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

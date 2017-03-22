/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

QueryData genPrograms(QueryContext& context) {
  QueryData results;
  QueryData regResults;
  queryKey(
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\"
      "Windows\\CurrentVersion\\Uninstall",
      regResults);
  for (const auto& rKey : regResults) {
    if (rKey.at("type") != "subkey") {
      continue;
    }
    QueryData appResults;
    std::string subkey = rKey.at("path");
    // make sure it's a sane uninstall key
    boost::smatch matches;
    boost::regex expression(
        "({[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+})"
        "$");
    if (!boost::regex_search(subkey, matches, expression)) {
      continue;
    }
    queryKey(subkey, appResults);
    Row r;
    r["identifying_number"] = matches[0];
    for (const auto& aKey : appResults) {
      if (aKey.at("name") == "DisplayName") {
        r["name"] = aKey.at("data");
      }
      if (aKey.at("name") == "DisplayVersion") {
        r["version"] = aKey.at("data");
      }
      if (aKey.at("name") == "InstallSource") {
        r["install_source"] = aKey.at("data");
      }
      if (aKey.at("name") == "Language") {
        r["language"] = aKey.at("data");
      }
      if (aKey.at("name") == "Publisher") {
        r["publisher"] = aKey.at("data");
      }
      if (aKey.at("name") == "UninstallString") {
        r["uninstall_string"] = aKey.at("data");
      }
      if (aKey.at("name") == "InstallDate") {
        r["install_date"] = aKey.at("data");
      }
    }
    results.push_back(r);
  }

  return results;
}
}
}

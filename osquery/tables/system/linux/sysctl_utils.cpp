/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/sysctl.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/posix/sysctl_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/mutex.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kSystemControlPath = "/proc/sys/";

void genControlInfo(const std::string& mib_path,
                    QueryData& results,
                    const std::map<std::string, std::string>& config) {
  if (isDirectory(mib_path).ok()) {
    // Iterate through the subitems and items.
    std::vector<std::string> items;
    if (listDirectoriesInDirectory(mib_path, items).ok()) {
      for (const auto& item : items) {
        genControlInfo(item, results, config);
      }
    }

    if (listFilesInDirectory(mib_path, items).ok()) {
      for (const auto& item : items) {
        genControlInfo(item, results, config);
      }
    }
    return;
  }

  // This is a file (leaf-control).
  Row r;
  r["name"] = mib_path.substr(kSystemControlPath.size());

  std::replace(r["name"].begin(), r["name"].end(), '/', '.');
  // No known way to convert name MIB to int array.
  r["subsystem"] = osquery::split(r.at("name"), ".")[0];

  if (isReadable(mib_path).ok()) {
    std::string content;
    readFile(mib_path, content);
    boost::trim(content);
    r["current_value"] = content;
  }

  if (config.count(r.at("name")) > 0) {
    r["config_value"] = config.at(r.at("name"));
  }
  r["type"] = "string";
  results.push_back(r);
}

void genControlInfo(int* oid,
                    size_t oid_size,
                    QueryData& results,
                    const std::map<std::string, std::string>& config) {
  // Get control size
  size_t response_size = CTL_MAX_VALUE;
  char response[CTL_MAX_VALUE + 1] = {0};
  if (sysctl(oid, oid_size, response, &response_size, 0, 0) != 0) {
    // Cannot request MIB data.
    return;
  }

  // Data is output, but no way to determine type (long, int, string, struct).
  Row r;
  r["oid"] = stringFromMIB(oid, oid_size);
  r["current_value"] = std::string(response);
  r["type"] = "string";
  results.push_back(r);
}

void genAllControls(QueryData& results,
                    const std::map<std::string, std::string>& config,
                    const std::string& subsystem) {
  // Linux sysctl subsystems are directories in /proc
  std::vector<std::string> subsystems;
  if (!listDirectoriesInDirectory("/proc/sys", subsystems).ok()) {
    return;
  }

  for (const auto& sub : subsystems) {
    if (subsystem.size() != 0 &&
        fs::path(sub).filename().string() != subsystem) {
      // Request is limiting subsystem.
      continue;
    }
    genControlInfo(sub, results, config);
  }
}

void genControlInfoFromName(const std::string& name,
                            QueryData& results,
                            const std::map<std::string, std::string>& config) {
  // Convert '.'-tokenized name to path.
  std::string name_path = name;
  std::replace(name_path.begin(), name_path.end(), '.', '/');
  auto mib_path = fs::path(kSystemControlPath) / name_path;

  genControlInfo(mib_path.string(), results, config);
}
}
}

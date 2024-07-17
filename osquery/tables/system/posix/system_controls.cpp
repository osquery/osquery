/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/posix/sysctl_utils.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kControlSettingsFiles = {"/etc/sysctl.conf"};

const std::vector<std::string> kControlSettingsDirs = {
    "/run/sysctl.d/%.conf",           "/etc/sysctl.d/%.conf",
    "/usr/local/lib/sysctl.d/%.conf", "/usr/lib/sysctl.d/%.conf",
    "/lib/sysctl.d/%.conf",
};

std::string stringFromMIB(const int* oid, size_t oid_size) {
  std::string result;
  for (size_t i = 0; i < oid_size; ++i) {
    // Walk an int-encoded MIB and return the string representation, '.'.
    if (result.size() > 0) {
      result += ".";
    }
    result += std::to_string(oid[i]);
  }
  return result;
}

void genControlInfoFromOIDString(
    const std::string& oid_string,
    QueryData& results,
    const std::map<std::string, std::string>& config) {
  int request[CTL_DEBUG_MAXID + 2] = {0};
  auto tokens = osquery::split(oid_string, ".");
  if (tokens.size() > CTL_DEBUG_MAXID) {
    // OID input string was too large.
    return;
  }

  // Convert the string into an int array.
  for (size_t i = 0; i < tokens.size(); ++i) {
    request[i] = atol(tokens.at(i).c_str());
  }
  genControlInfo((int*)request, tokens.size(), results, config);
}

void genControlConfigFromPath(const std::string& path,
                              std::map<std::string, std::string>& config) {
  std::string content;
  if (!osquery::readFile(path, content).ok()) {
    return;
  }

  for (auto& line : osquery::split(content, "\n")) {
    boost::trim(line);
    if (line[0] == '#' || line[0] == ';') {
      continue;
    }

    // Try to tokenize the config line using '='.
    auto detail = osquery::split(line, "=");
    if (detail.size() == 2) {
      boost::trim(detail[0]);
      boost::trim(detail[1]);
      config[detail[0]] = detail[1];
    }
  }
}

QueryData genSystemControls(QueryContext& context) {
  QueryData results;

  // Read the sysctl.conf values.
  std::map<std::string, std::string> config;
  for (const auto& path : kControlSettingsFiles) {
    genControlConfigFromPath(path, config);
  }

  for (const auto& dirs : kControlSettingsDirs) {
    std::vector<std::string> configs;
    if (resolveFilePattern(dirs, configs).ok()) {
      for (const auto& path : configs) {
        genControlConfigFromPath(path, config);
      }
    }
  }

  // Iterate through the sysctl-defined macro of control types.
  if (context.constraints["name"].exists(EQUALS)) {
    // Request MIB information by the description (name).
    auto names = context.constraints["name"].getAll(EQUALS);
    for (const auto& name : names) {
      genControlInfoFromName(name, results, config);
    }
  } else if (context.constraints["oid"].exists(EQUALS)) {
    // Request MIB by OID as a string, parse into set of INTs.
    auto oids = context.constraints["oid"].getAll(EQUALS);
    for (const auto& oid_string : oids) {
      genControlInfoFromOIDString(oid_string, results, config);
    }
  } else if (context.constraints["subsystem"].exists(EQUALS)) {
    // Limit the MIB search to a subsystem name (first find the INT).
    auto subsystems = context.constraints["subsystem"].getAll(EQUALS);
    for (const auto& subsystem : subsystems) {
      genAllControls(results, config, subsystem);
    }
  } else {
    genAllControls(results, config, "");
  }

  return results;
}
}
}

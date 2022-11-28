/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <boost/algorithm/string.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

const std::string kMemInfoPath = {"/proc/meminfo"};

const std::map<std::string, std::string> kMemInfoMap = {
    {"memory_total", "MemTotal:"},
    {"memory_free", "MemFree:"},
    {"memory_available", "MemAvailable:"},
    {"buffers", "Buffers:"},
    {"cached", "Cached:"},
    {"swap_cached", "SwapCached:"},
    {"active", "Active:"},
    {"inactive", "Inactive:"},
    {"swap_total", "SwapTotal:"},
    {"swap_free", "SwapFree:"},
};

QueryData getMemoryInfo(QueryContext& context) {
  QueryData results;
  Row r;

  std::string meminfo_content;
  if (forensicReadFile(kMemInfoPath, meminfo_content).ok()) {
    // Able to read meminfo file, now grab info we want
    for (const auto& line : split(meminfo_content, "\n")) {
      std::vector<std::string> tokens;
      boost::split(
          tokens, line, boost::is_any_of("\t "), boost::token_compress_on);
      // Look for mapping
      for (const auto& singleMap : kMemInfoMap) {
        if (line.find(singleMap.second) == 0) {
          auto const value_exp = tryTo<long>(tokens[1], 10);
          if (value_exp.isValue()) {
            r[singleMap.first] = BIGINT(value_exp.get() * 1024l);
          }
          break;
        }
      }
    }
  }
  results.push_back(r);
  return results;
}
}
}

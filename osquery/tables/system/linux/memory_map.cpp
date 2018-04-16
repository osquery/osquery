/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kIOMemLocation{"/proc/iomem"};

QueryData genMemoryMap(QueryContext& context) {
  QueryData results;

  std::vector<std::string> regions;
  std::string content;
  readFile(kIOMemLocation, content);

  regions = osquery::split(content, "\n");
  for (const auto& line : regions) {
    auto b1 = line.find_first_of("-");
    auto b2 = line.find_first_of(" : ");
    if (b1 == std::string::npos || b2 == std::string::npos) {
      continue;
    }

    Row r;
    r["start"] = "0x" + line.substr(0, b1);
    if (b1 == line.size() || line.size() <= b2 + 3) {
      continue;
    }
    r["end"] = "0x" + line.substr(b1 + 1, b2 - b1);
    r["name"] = line.substr(b2 + 3);
    results.push_back(r);
  }

  return results;
}
}
}

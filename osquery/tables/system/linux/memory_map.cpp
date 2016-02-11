/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kMemoryMapLocation = "/sys/firmware/memmap";

QueryData genMemoryMap(QueryContext& context) {
  QueryData results;

  // Linux memory map is exposed in /sys.
  std::vector<std::string> regions;
  auto status = listDirectoriesInDirectory(kMemoryMapLocation, regions);
  if (!status.ok()) {
    return {};
  }

  for (const auto& index : regions) {
    fs::path index_path(index);
    Row r;
    r["region"] = index_path.filename().string();

    // The type is a textual description
    std::string content;
    readFile(index_path / "type", content);
    boost::trim(content);
    r["type"] = content;

    // Keep these in 0xFFFF (hex) form.
    readFile(index_path / "start", content);
    boost::trim(content);
    r["start"] = content;

    readFile(index_path / "end", content);
    boost::trim(content);
    r["end"] = content;

    results.push_back(r);
  }

  return results;
}
}
}

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem/filesystem.h>

namespace osquery {
namespace tables {

void genDescriptors(const std::string& process,
                    const std::map<std::string, std::string>& descriptors,
                    QueryData& results) {
  for (const auto& fd : descriptors) {
    if (fd.second.find("socket:") != std::string::npos ||
        fd.second.find("anon_inode:") != std::string::npos ||
        fd.second.find("pipe:") != std::string::npos) {
      // This is NOT a vnode/file descriptor.
      continue;
    }

    Row r;
    r["pid"] = process;
    r["fd"] = fd.first;
    r["path"] = fd.second;
    results.push_back(r);
  }

  return;
}

QueryData genOpenFiles(QueryContext& context) {
  QueryData results;

  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  } else {
    osquery::procProcesses(pids);
  }

  for (const auto& process : pids) {
    std::map<std::string, std::string> descriptors;
    if (osquery::procDescriptors(process, descriptors).ok()) {
      genDescriptors(process, descriptors, results);
    }
  }

  return results;
}
}
}

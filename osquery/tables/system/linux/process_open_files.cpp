/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

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

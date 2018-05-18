/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#define DECLARE_TABLE_IMPLEMENTATION_process_open_files
#include <generated/tables/tbl_process_open_files_defs.hpp>

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

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

#include <boost/algorithm/string/predicate.hpp>

namespace osquery {
namespace tables {

namespace {

// Namespace descriptors (nsfs) readlink to "<type>:[<inode>]", e.g.
// "net:[4026531833]". Like sockets and pipes they are not files and have
// no filesystem path. Match on the prefix: readlink targets of real files
// are absolute paths and can never start this way.
bool isNamespaceDescriptor(const std::string& target) {
  static const std::vector<std::string> kNamespaceTypes = {
      "cgroup",
      "ipc",
      "mnt",
      "net",
      "pid",
      "time",
      "user",
      "uts",
  };
  if (target.empty() || target.back() != ']') {
    return false;
  }
  for (const auto& type : kNamespaceTypes) {
    if (target.compare(0, type.size() + 2, type + ":[") == 0) {
      return true;
    }
  }
  return false;
}

} // namespace

void genDescriptors(const std::string& process,
                    const std::map<std::string, std::string>& descriptors,
                    QueryData& results) {
  for (const auto& fd : descriptors) {
    // Sockets, pipes and anonymous inodes readlink to "socket:[<inode>]",
    // "pipe:[<inode>]" and "anon_inode:<type>". Match on the prefix, as for
    // namespaces: a regular file may contain these strings in its path.
    if (boost::algorithm::starts_with(fd.second, "socket:[") ||
        boost::algorithm::starts_with(fd.second, "anon_inode:") ||
        boost::algorithm::starts_with(fd.second, "pipe:[") ||
        isNamespaceDescriptor(fd.second)) {
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

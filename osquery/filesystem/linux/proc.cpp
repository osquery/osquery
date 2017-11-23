/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <linux/limits.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace osquery {

const std::string kLinuxProcPath = "/proc";

Status procProcesses(std::set<std::string>& processes) {
  // Iterate over each process-like directory in proc.
  boost::filesystem::directory_iterator it(kLinuxProcPath), end;
  try {
    for (; it != end; ++it) {
      if (boost::filesystem::is_directory(it->status())) {
        // See #792: std::regex is incomplete until GCC 4.9
        if (std::atoll(it->path().leaf().string().c_str()) > 0) {
          processes.insert(it->path().leaf().string());
        }
      }
    }
  } catch (const boost::filesystem::filesystem_error& e) {
    VLOG(1) << "Exception iterating Linux processes " << e.what();
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

Status procDescriptors(const std::string& process,
                       std::map<std::string, std::string>& descriptors) {
  auto descriptors_path = kLinuxProcPath + "/" + process + "/fd";
  try {
    // Access to the process' /fd may be restricted.
    boost::filesystem::directory_iterator it(descriptors_path), end;
    for (; it != end; ++it) {
      auto fd = it->path().leaf().string();
      std::string linkname;
      if (procReadDescriptor(process, fd, linkname).ok()) {
        descriptors[fd] = linkname;
      }
    }
  } catch (boost::filesystem::filesystem_error& e) {
    return Status(1, "Cannot access descriptors for " + process);
  }

  return Status(0, "OK");
}

Status procReadDescriptor(const std::string& process,
                          const std::string& descriptor,
                          std::string& result) {
  auto link = kLinuxProcPath + "/" + process + "/fd/" + descriptor;

  char result_path[PATH_MAX] = {0};
  auto size = readlink(link.c_str(), result_path, sizeof(result_path) - 1);
  if (size >= 0) {
    result = std::string(result_path);
    return Status(0);
  }
  return Status(1, "Could not read path");
}
}

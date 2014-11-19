// Copyright 2004-present Facebook. All Rights Reserved.

#include <exception>

#include <unistd.h>

#include <boost/regex.hpp>
#include <boost/filesystem.hpp>

#include <glog/logging.h>

#include "osquery/filesystem.h"

namespace osquery {

const std::string kLinuxProcPath = "/proc";

Status procProcesses(std::vector<std::string>& processes) {
  boost::regex process_filter("\\d+");

  // Iterate over each process-like directory in proc.
  boost::filesystem::directory_iterator it(kLinuxProcPath), end;
  try {
    for (; it != end; ++it) {
      if (boost::filesystem::is_directory(it->status())) {
        boost::smatch what;
        if (boost::regex_match(
                it->path().leaf().string(), what, process_filter)) {
          processes.push_back(it->path().leaf().string());
        }
      }
    }
  } catch (boost::filesystem::filesystem_error& e) {
    VLOG(1) << "Exception iterating Linux processes " << e.what();
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

Status procDescriptors(const std::string& process,
                       std::vector<std::string>& descriptors) {
  auto descriptors_path = kLinuxProcPath + "/" + process + "/fd";
  try {
    // Access to the process' /fd may be restricted.
    boost::filesystem::directory_iterator it(descriptors_path), end;
    for (; it != end; ++it) {
      descriptors.push_back(it->path().leaf().string());
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
  auto path_max = pathconf(link.c_str(), _PC_PATH_MAX);
  auto result_path = (char*)malloc(path_max);

  memset(result_path, 0, path_max);
  auto size = readlink(link.c_str(), result_path, path_max);
  if (size >= 0) {
    result = std::string(result_path);
  }

  free(result_path);
  if (size >= 0) {
    return Status(0, "OK");
  } else {
    return Status(1, "Could not read path");
  }
}
}

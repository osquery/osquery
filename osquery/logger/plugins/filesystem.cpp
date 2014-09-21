// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger/plugin.h"

#include <algorithm>
#include <exception>
#include <ios>
#include <fstream>
#include <mutex>
#include <thread>

#include <gflags/gflags.h>
#include <glog/logging.h>

using osquery::Status;

namespace osquery {

std::mutex filesystemLoggerPluginMutex;

class FilesystemLoggerPlugin : public LoggerPlugin {
 public:
  std::string log_path;
  FilesystemLoggerPlugin() {
    log_path = FLAGS_log_dir + "osqueryd.results.log";
  }

  virtual Status logString(const std::string& s) {
    std::lock_guard<std::mutex> lock(filesystemLoggerPluginMutex);
    try {
      VLOG(3) << "filesystem logger plugin: logging to " << log_path;
      std::ofstream log_stream(log_path,
                               std::ios_base::app | std::ios_base::out);
      if (log_stream.fail()) {
        return Status(1, "error opening file: " + log_path);
      }
      log_stream << s << std::endl;
    } catch (const std::exception& e) {
      return Status(1, e.what());
    }
    return Status(0, "OK");
  }
};

REGISTER_LOGGER_PLUGIN("filesystem",
                       std::make_shared<osquery::FilesystemLoggerPlugin>());
}

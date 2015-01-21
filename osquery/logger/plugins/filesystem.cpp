/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <exception>
#include <mutex>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/logger/plugin.h>

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

      // The results log may contain sensitive information if run as root.
      auto status = writeTextFile(log_path, s, 0640, true);
      if (!status.ok()) {
        return status;
      }
    } catch (const std::exception& e) {
      return Status(1, e.what());
    }
    return Status(0, "OK");
  }
};

REGISTER_LOGGER_PLUGIN("filesystem",
                       std::make_shared<osquery::FilesystemLoggerPlugin>());
}

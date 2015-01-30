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

using osquery::Status;

namespace osquery {

std::mutex filesystemLoggerPluginMutex;

class FilesystemLoggerPlugin : public LoggerPlugin {
 public:
  Status setUp();
  Status logString(const std::string& s);

 private:
  std::string log_path_;
};

namespace registry {
auto FilesystemLoggerPluginRegistryItem =
    NewRegistry::add<FilesystemLoggerPlugin>("logger", "filesystem");
}

Status FilesystemLoggerPlugin::setUp() {
  log_path_ = FLAGS_log_dir + "osqueryd.results.log";
  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::logString(const std::string& s) {
  std::lock_guard<std::mutex> lock(filesystemLoggerPluginMutex);
  try {
    VLOG(3) << "filesystem logger plugin: logging to " << log_path_;

    // The results log may contain sensitive information if run as root.
    auto status = writeTextFile(log_path_, s, 0640, true);
    if (!status.ok()) {
      return status;
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

class TestLoggerPlugin : public LoggerPlugin {
 public:
  TestLoggerPlugin() { test_ = "hello friend"; }
  Status logString(const std::string& s) { return Status(0, "OK"); }

 private:
  std::string test_;
};
}

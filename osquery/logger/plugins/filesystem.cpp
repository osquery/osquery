// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger/plugin.h"

#include <algorithm>
#include <exception>
#include <ios>
#include <fstream>
#include <thread>

#include <gflags/gflags.h>
#include <glog/logging.h>

using osquery::Status;

namespace osquery {
namespace logger {

DEFINE_string(
    log_path, "/var/log/osquery.log",
    "The path of the log file to be used if filesystem logging is enabled.");

class FilesystemLoggerPlugin : public LoggerPlugin {
public:
  FilesystemLoggerPlugin() {}

  Status logString(const std::string &s) {
    try {
      std::ofstream log_stream(FLAGS_log_path,
                               std::ios_base::app | std::ios_base::out);
      log_stream << s << std::endl;
    }
    catch (const std::exception &e) {
      return Status(1, e.what());
    }
    return Status(0, "OK");
  }

  virtual ~FilesystemLoggerPlugin() {}
};

REGISTER_LOGGER_PLUGIN(
    "filesystem", std::make_shared<osquery::logger::FilesystemLoggerPlugin>());
}
}

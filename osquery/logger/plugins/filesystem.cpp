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

namespace fs = boost::filesystem;

namespace osquery {

FLAG(string,
     logger_path,
     "/var/log/osquery/",
     "Directory path for ERROR/WARN/INFO and results logging");
/// Legacy, backward compatible "osquery_log_dir" CLI option.
FLAG_ALIAS(std::string, osquery_log_dir, logger_path);

const std::string kFilesystemLoggerFilename = "osqueryd.results.log";

std::mutex filesystemLoggerPluginMutex;

class FilesystemLoggerPlugin : public LoggerPlugin {
 public:
  Status setUp();
  Status logString(const std::string& s);
  Status init(const std::string& name, const std::vector<StatusLogLine>& log);
  Status logStatus(const std::vector<StatusLogLine>& log);

 private:
  fs::path log_path_;
};

REGISTER(FilesystemLoggerPlugin, "logger", "filesystem");

Status FilesystemLoggerPlugin::setUp() {
  log_path_ = fs::path(FLAGS_logger_path) / kFilesystemLoggerFilename;
  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::logString(const std::string& s) {
  std::lock_guard<std::mutex> lock(filesystemLoggerPluginMutex);
  try {
    // The results log may contain sensitive information if run as root.
    auto status = writeTextFile(log_path_.string(), s, 0640, true);
    if (!status.ok()) {
      return status;
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::logStatus(
    const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    // Emit this intermediate log to the glog filesystem logger.
    google::LogMessage(item.filename.c_str(),
                       item.line,
                       (google::LogSeverity)item.severity).stream()
        << item.message;
  }

  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::init(const std::string& name,
                                    const std::vector<StatusLogLine>& log) {
  // Stop the internal glog facilities.
  google::ShutdownGoogleLogging();

  // The log dir is used for status logging and the filesystem results logs.
  if (isWritable(FLAGS_logger_path).ok()) {
    FLAGS_log_dir = FLAGS_logger_path;
    FLAGS_logtostderr = false;
  } else {
    // If we cannot write logs to the filesystem, fallback to stderr.
    // The caller (flags/options) might 'also' be logging to stderr using
    // debug, verbose, etc.
    FLAGS_logtostderr = true;
  }

  // Restart the glog facilities using the name init was provided.
  google::InitGoogleLogging(name.c_str());

  // We may violate glog global object assumptions. So set names manually.
  auto basename = (log_path_.parent_path() / name).string();
  google::SetLogDestination(google::INFO, (basename + ".INFO.").c_str());
  google::SetLogDestination(google::WARNING, (basename + ".WARNING.").c_str());
  google::SetLogDestination(google::ERROR, (basename + ".ERROR.").c_str());

  // Store settings for logging to stderr.
  bool log_to_stderr = FLAGS_logtostderr;
  bool also_log_to_stderr = FLAGS_alsologtostderr;
  FLAGS_alsologtostderr = false;
  FLAGS_logtostderr = false;

  // Now funnel the intermediate status logs provided to init.
  logStatus(log);

  // Restore settings for logging to stderr.
  FLAGS_logtostderr = log_to_stderr;
  FLAGS_alsologtostderr = also_log_to_stderr;

  // The filesystem logger cheats and uses Glog to log to the filesystem so
  // we can return failure here and stop the custom log sink.
  return Status(1, "No status logger used for filesystem");
}
}

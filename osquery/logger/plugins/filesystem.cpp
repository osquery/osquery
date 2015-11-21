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

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

// This is the mode that glog uses for logfiles.  Must be at the top level
// (i.e. outside of the `osquery` namespace).
DECLARE_int32(logfile_mode);

namespace osquery {

FLAG(string,
     logger_path,
     "/var/log/osquery/",
     "Directory path for ERROR/WARN/INFO and results logging");

FLAG(int32,
     logger_mode,
     0640,
     "Mode for log files (default '0640')");

/// Legacy, backward compatible "osquery_log_dir" CLI option.
FLAG_ALIAS(std::string, osquery_log_dir, logger_path);

const std::string kFilesystemLoggerFilename = "osqueryd.results.log";
const std::string kFilesystemLoggerSnapshots = "osqueryd.snapshots.log";
const std::string kFilesystemLoggerHealth = "osqueryd.health.log";

std::mutex filesystemLoggerPluginMutex;

class FilesystemLoggerPlugin : public LoggerPlugin {
 public:
  Status setUp();
  Status logString(const std::string& s);
  Status logStringToFile(const std::string& s, const std::string& filename);
  Status logSnapshot(const std::string& s);
  Status logHealth(const std::string& s);
  Status init(const std::string& name, const std::vector<StatusLogLine>& log);
  Status logStatus(const std::vector<StatusLogLine>& log);

 private:
  fs::path log_path_;
};

REGISTER(FilesystemLoggerPlugin, "logger", "filesystem");

Status FilesystemLoggerPlugin::setUp() {
  log_path_ = fs::path(FLAGS_logger_path);

  // Ensure that the glog status logs use the same mode as our results log.
  FLAGS_logfile_mode = FLAGS_logger_mode;

  // Ensure that we create the results log here.
  auto status = logString("");
  if (!status.ok()) {
    return status;
  }

  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::logString(const std::string& s) {
  return logStringToFile(s, kFilesystemLoggerFilename);
}

Status FilesystemLoggerPlugin::logStringToFile(const std::string& s,
                                               const std::string& filename) {
  std::lock_guard<std::mutex> lock(filesystemLoggerPluginMutex);
  try {
    auto status = writeTextFile((log_path_ / filename).string(), s, FLAGS_logger_mode, true);
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
    // Emit this intermediate log to the Glog filesystem logger.
    google::LogMessage(item.filename.c_str(),
                       item.line,
                       (google::LogSeverity)item.severity).stream()
        << item.message;
  }

  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::logSnapshot(const std::string& s) {
  // Send the snapshot data to a separate filename.
  return logStringToFile(s, kFilesystemLoggerSnapshots);
}

Status FilesystemLoggerPlugin::logHealth(const std::string& s) {
  return logStringToFile(s, kFilesystemLoggerHealth);
}

Status FilesystemLoggerPlugin::init(const std::string& name,
                                    const std::vector<StatusLogLine>& log) {
  // Stop the internal Glog facilities.
  google::ShutdownGoogleLogging();

  // The log dir is used for status logging and the filesystem results logs.
  if (isWritable(log_path_.string()).ok()) {
    FLAGS_log_dir = log_path_.string();
    FLAGS_logtostderr = false;
  } else {
    // If we cannot write logs to the filesystem, fallback to stderr.
    // The caller (flags/options) might 'also' be logging to stderr using
    // debug, verbose, etc.
    FLAGS_logtostderr = true;
  }

  // Restart the Glog facilities using the name `init` was provided.
  google::InitGoogleLogging(name.c_str());

  // We may violate Glog global object assumptions. So set names manually.
  auto basename = (log_path_ / name).string();
  google::SetLogDestination(google::INFO, (basename + ".INFO.").c_str());
  google::SetLogDestination(google::WARNING, (basename + ".WARNING.").c_str());
  google::SetLogDestination(google::ERROR, (basename + ".ERROR.").c_str());

  // Store settings for logging to stderr.
  bool log_to_stderr = FLAGS_logtostderr;
  bool also_log_to_stderr = FLAGS_alsologtostderr;
  int stderr_threshold = FLAGS_stderrthreshold;
  FLAGS_alsologtostderr = false;
  FLAGS_logtostderr = false;
  FLAGS_stderrthreshold = 5;

  // Now funnel the intermediate status logs provided to `init`.
  logStatus(log);

  // Restore settings for logging to stderr.
  FLAGS_logtostderr = log_to_stderr;
  FLAGS_alsologtostderr = also_log_to_stderr;
  FLAGS_stderrthreshold = stderr_threshold;

  // The filesystem logger cheats and uses Glog to log to the filesystem so
  // we can return failure here and stop the custom log sink.
  return Status(1, "No status logger used for filesystem");
}
}

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "filesystem_logger.h"

#include <exception>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/config/default_paths.h>

namespace fs = boost::filesystem;

/**
 * This is the mode that Glog uses for logfiles.
 * Must be at the top level (i.e. outside of the `osquery` namespace).
 */
DECLARE_int32(logfile_mode);

namespace osquery {

FLAG(string,
     logger_path,
     OSQUERY_LOG_HOME,
     "Directory path for ERROR/WARN/INFO and results logging");
/// Legacy, backward compatible "osquery_log_dir" CLI option.
FLAG_ALIAS(std::string, osquery_log_dir, logger_path);

FLAG(int32, logger_mode, 0640, "Decimal mode for log files (default '0640')");

const std::string kFilesystemLoggerFilename = "osqueryd.results.log";
const std::string kFilesystemLoggerSnapshots = "osqueryd.snapshots.log";

Status FilesystemLoggerPlugin::setUp() {
  log_path_ = fs::path(FLAGS_logger_path);

  // Ensure that the Glog status logs use the same mode as our results log.
  // Glog 0.3.4 does not support a logfile mode.
  // FLAGS_logfile_mode = FLAGS_logger_mode;

  // Ensure that we create the results log here.
  return logStringToFile("", kFilesystemLoggerFilename, true);
}

Status FilesystemLoggerPlugin::logString(const std::string& s) {
  return logStringToFile(s, kFilesystemLoggerFilename);
}

Status FilesystemLoggerPlugin::logStringToFile(const std::string& s,
                                               const std::string& filename,
                                               bool empty) {
  WriteLock lock(mutex_);
  Status status;
  try {
    status = writeTextFile((log_path_ / filename).string(),
                           (empty) ? "" : s + '\n',
                           FLAGS_logger_mode);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return status;
}

Status FilesystemLoggerPlugin::logStatus(
    const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    // Emit this intermediate log to the Glog filesystem logger.
    google::LogMessage(item.filename.c_str(),
                       static_cast<int>(item.line),
                       (google::LogSeverity)item.severity)
            .stream()
        << item.message;
  }

  return Status(0, "OK");
}

Status FilesystemLoggerPlugin::logSnapshot(const std::string& s) {
  // Send the snapshot data to a separate filename.
  return logStringToFile(s, kFilesystemLoggerSnapshots);
}

void FilesystemLoggerPlugin::init(const std::string& name,
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

  google::SetLogDestination(google::GLOG_INFO, (basename + ".INFO.").c_str());
  google::SetLogDestination(google::GLOG_WARNING,
                            (basename + ".WARNING.").c_str());
  google::SetLogDestination(google::GLOG_ERROR, (basename + ".ERROR.").c_str());

  // Store settings for logging to stderr.
  bool log_to_stderr = FLAGS_logtostderr;
  bool also_log_to_stderr = FLAGS_alsologtostderr;
  int stderr_threshold = FLAGS_stderrthreshold;
  FLAGS_alsologtostderr = false;
  FLAGS_logtostderr = false;
  FLAGS_stderrthreshold = 5;

  // Now funnel the intermediate status logs provided to `init`.
  logStatus(log);

  // The filesystem logger cheats and uses Glog to log to the filesystem so
  // we can return failure here and stop the custom log sink.
  // Restore settings for logging to stderr.
  FLAGS_logtostderr = log_to_stderr;
  FLAGS_alsologtostderr = also_log_to_stderr;
  FLAGS_stderrthreshold = stderr_threshold;
}
}

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "filesystem_logger.h"
#include "logrotate.h"

#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/config/default_paths.h>

#include <exception>

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

FLAG(bool, logger_rotate, false, "Use filesystem log rotation");
FLAG(uint64,
     logger_rotate_max_files,
     25,
     "Max number of files to keep in rotation");
FLAG(uint64,
     logger_rotate_size,
     25 * 1024 * 1024,
     "Size for each filesystem log in bytes");

FLAG(int32, logger_mode, 0640, "Octal mode for log files (default '0640')");

const std::string kFilesystemLoggerFilename = "osqueryd.results.log";
const std::string kFilesystemLoggerSnapshots = "osqueryd.snapshots.log";

bool LogRotate::shouldRotate() {
  return this->fileSize(path_) >= this->getRotateSize();
}

Status LogRotate::rotate(size_t max_files) {
  if (!pathExists(path_)) {
    return Status::failure("Path under rotation does not exist");
  }
  size_t offset = 1;
  std::vector<std::string> moves{getRotateFile(offset)};
  while (this->pathExists(moves.back())) {
    moves.push_back(getRotateFile(++offset));
  }

  auto s = this->moveFiles(moves, max_files);
  if (!s.ok()) {
    return s;
  }
  return this->moveFile(path_, *moves.begin());
}

size_t LogRotate::getRotateSize() {
  return FLAGS_logger_rotate_size;
}

size_t LogRotate::fileSize(const std::string& filepath) {
  boost::system::error_code ec;
  auto size = fs::file_size(filepath, ec);
  return (ec) ? 0 : size;
}

bool LogRotate::pathExists(const std::string& path) {
  return osquery::pathExists(path).ok();
}

Status LogRotate::removeFile(const std::string& path) {
  return osquery::removePath(path);
}

Status LogRotate::moveFile(const std::string& source, const std::string& dest) {
  return osquery::movePath(source, dest);
}

Status LogRotate::compressFile(const std::string& source,
                               const std::string& dest) {
  return osquery::compress(source, dest);
}

std::string LogRotate::getRotateFile(size_t offset) {
  auto filename = path_ + '.' + std::to_string(offset);
  if (offset > kUncompressedCount) {
    filename += ".zst";
  }
  return filename;
}

Status LogRotate::moveFiles(const std::vector<std::string>& moves,
                            size_t max_files) {
  if (moves.size() == 1) {
    return Status::success();
  }

  for (size_t i = moves.size() - 1; i > 0; i--) {
    if (i == kUncompressedCount) {
      auto s = this->compressFile(moves[i - 1], moves[i]);
      if (!s.ok()) {
        return s;
      }
    } else {
      auto s = this->moveFile(moves[i - 1], moves[i]);
      if (!s.ok()) {
        return s;
      }
    }
  }

  for (size_t i = moves.size() - 1; i >= max_files; i--) {
    auto s = this->removeFile(moves[i]);
    if (!s.ok()) {
      return s;
    }
  }

  return Status::success();
}

struct FilesystemLoggerPlugin::impl {
  /// The folder where Glog and the result/snapshot files are written.
  boost::filesystem::path log_path;

  /// Results log rotator.
  std::unique_ptr<LogRotate> results_rotate{nullptr};
  /// Snapshot log rotator.
  std::unique_ptr<LogRotate> snapshot_rotate{nullptr};

  /// Filesystem results log writer mutex.
  Mutex snapshot_mutex;
  /// Filesystem snapshot log write mutex.
  Mutex results_mutex;
};

FilesystemLoggerPlugin::FilesystemLoggerPlugin()
    : pimpl_(std::make_unique<FilesystemLoggerPlugin::impl>()) {}

FilesystemLoggerPlugin::~FilesystemLoggerPlugin() = default;

Status FilesystemLoggerPlugin::setUp() {
  pimpl_->log_path = fs::path(FLAGS_logger_path);
  pimpl_->results_rotate = std::make_unique<LogRotate>(
      (pimpl_->log_path / kFilesystemLoggerFilename).string());
  pimpl_->snapshot_rotate = std::make_unique<LogRotate>(
      (pimpl_->log_path / kFilesystemLoggerSnapshots).string());

  // Ensure that the Glog status logs use the same mode as our results log.
  // Glog 0.3.4 does not support a logfile mode.
  // FLAGS_logfile_mode = FLAGS_logger_mode;

  // Ensure that we create the results log here.
  WriteLock lock(pimpl_->results_mutex);
  return logStringToFile("", kFilesystemLoggerFilename, true);
}

Status FilesystemLoggerPlugin::logString(const std::string& s) {
  WriteLock lock(pimpl_->results_mutex);
  if (FLAGS_logger_rotate && pimpl_->results_rotate->shouldRotate()) {
    auto s = pimpl_->results_rotate->rotate(FLAGS_logger_rotate_max_files);
    if (!s.ok()) {
      return s;
    }
  }

  return logStringToFile(s, kFilesystemLoggerFilename);
}

Status FilesystemLoggerPlugin::logSnapshot(const std::string& s) {
  // Send the snapshot data to a separate filename.
  WriteLock lock(pimpl_->snapshot_mutex);
  if (FLAGS_logger_rotate && pimpl_->snapshot_rotate->shouldRotate()) {
    auto s = pimpl_->snapshot_rotate->rotate(FLAGS_logger_rotate_max_files);
    if (!s.ok()) {
      return s;
    }
  }

  return logStringToFile(s, kFilesystemLoggerSnapshots);
}

Status FilesystemLoggerPlugin::logStringToFile(const std::string& s,
                                               const std::string& filename,
                                               bool empty) {
  Status status;
  try {
    auto filepath = (pimpl_->log_path / filename).string();
    status =
        writeTextFile(filepath, (empty) ? "" : s + '\n', FLAGS_logger_mode);
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

void FilesystemLoggerPlugin::init(const std::string& name,
                                  const std::vector<StatusLogLine>& log) {
  // Stop the internal Glog facilities.
  google::ShutdownGoogleLogging();

  // The log dir is used for status logging and the filesystem results logs.
  if (isWritable(pimpl_->log_path.string()).ok()) {
    FLAGS_log_dir = pimpl_->log_path.string();
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
  auto basename = (pimpl_->log_path / name).string();

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
} // namespace osquery

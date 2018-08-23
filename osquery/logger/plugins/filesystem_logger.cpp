/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <exception>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/flagalias.h"

namespace fs = boost::filesystem;

/**
 * This is the mode that Glog uses for logfiles.
 * Must be at the top level (i.e. outside of the `osquery` namespace).
 */
DECLARE_int32(logfile_mode);

namespace osquery {

DECLARE_string(logger_path);
/// Legacy, backward compatible "osquery_log_dir" CLI option.
FLAG_ALIAS(std::string, osquery_log_dir, logger_path);

DECLARE_int32(logger_mode);

const std::string kFilesystemLoggerFilename = "osqueryd.results.log";
const std::string kFilesystemLoggerSnapshots = "osqueryd.snapshots.log";

class FilesystemLoggerPlugin : public LoggerPlugin {
 public:
  Status setUp() override;

  /// Log results (differential) to a distinct path.
  Status logString(const std::string& s) override;

  /// Log snapshot data to a distinct path.
  Status logSnapshot(const std::string& s) override;

  /**
   * @brief Initialize the logger plugin after osquery has begun.
   *
   * The filesystem logger plugin is somewhat unique, it is the only logger
   * that will return an error during initialization. This allows Glog to
   * write directly to files.
   */
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

 private:
  /// The plugin-internal filesystem writer method.
  Status logStringToFile(const std::string& s,
                         const std::string& filename,
                         bool empty = false);

 private:
  /// The folder where Glog and the result/snapshot files are written.
  fs::path log_path_;

  /// Filesystem writer mutex.
  Mutex mutex_;

 private:
  FRIEND_TEST(FilesystemLoggerTests, test_filesystem_init);
};

REGISTER(FilesystemLoggerPlugin, "logger", "filesystem");

Status FilesystemLoggerPlugin::setUp() {
  log_path_ = fs::path(FLAGS_logger_path);

  // Ensure that the Glog status logs use the same mode as our results log.
  FLAGS_logfile_mode = FLAGS_logger_mode;

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

Status FilesystemLoggerPlugin::logSnapshot(const std::string& s) {
  // Send the snapshot data to a separate filename.
  return logStringToFile(s, kFilesystemLoggerSnapshots);
}

void FilesystemLoggerPlugin::init(const std::string& name,
                                  const std::vector<StatusLogLine>& log) {

}
}

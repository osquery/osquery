#pragma once

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <exception>

#include <osquery/filesystem/filesystem.h>
#include <osquery/registry_factory.h>
#include <osquery/plugins/logger.h>
#include <osquery/flagalias.h>

namespace osquery {

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

  /// Write a status to Glog.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  /// The plugin-internal filesystem writer method.
  Status logStringToFile(const std::string& s,
                         const std::string& filename,
                         bool empty = false);

 private:
  /// The folder where Glog and the result/snapshot files are written.
  boost::filesystem::path log_path_;

  /// Filesystem writer mutex.
  Mutex mutex_;

  /*
 private:
  FRIEND_TEST(FilesystemLoggerTests, test_filesystem_init);
  */
};

REGISTER(FilesystemLoggerPlugin, "logger", "filesystem");
}

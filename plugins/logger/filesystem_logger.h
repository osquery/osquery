/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/flagalias.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry_factory.h>

#include <memory>

namespace osquery {

class FilesystemLoggerPlugin : public LoggerPlugin {
 public:
  FilesystemLoggerPlugin();
  virtual ~FilesystemLoggerPlugin();

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
  struct impl;
  std::unique_ptr<impl> pimpl_{nullptr};
};

REGISTER(FilesystemLoggerPlugin, "logger", "filesystem");
}

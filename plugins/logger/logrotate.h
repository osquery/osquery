/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/status/status.h>

#include <string>
#include <vector>

namespace osquery {

class LogRotate {
  /// Number of rotated log files that remain uncompressed.
  static const size_t kUncompressedCount{1};

 public:
  LogRotate(const std::string& path) : path_(path) {}
  virtual ~LogRotate() = default;

  /// Check if the current file under rotation has exceeded the limits.
  bool shouldRotate();

  /// Applies rotation to the target accumulating file.
  Status rotate(size_t max_files);

 protected:
  /// Allow child classes to fake the implementation to assist testing.
  virtual size_t fileSize(const std::string& filepath);
  virtual bool pathExists(const std::string& path);
  virtual Status removeFile(const std::string& path);
  virtual Status moveFile(const std::string& source, const std::string& dest);
  virtual Status compressFile(const std::string& source,
                              const std::string& dest);
  virtual size_t getRotateSize();

 private:
  /// Helper to maintain consistent naming.
  std::string getRotateFile(size_t offset);
  /// Move a series of files after a rotation occurs.
  Status moveFiles(const std::vector<std::string>& moves, size_t max_files);

 private:
  /// Full path to file under rotation.
  std::string path_;
};

} // namespace osquery
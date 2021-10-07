/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <functional>

#include <boost/noncopyable.hpp>
#include <tsk/libtsk.h>

namespace osquery {
class SleuthkitHelper : private boost::noncopyable {
 public:
  explicit SleuthkitHelper(const std::string& device_path)
      : image_(std::make_shared<TskImgInfo>()),
        volume_(std::make_shared<TskVsInfo>()),
        device_path_(device_path) {}

  // Volume partition iterator to identify minimum Windows OS size.
  void partitionsMinOsSize(
      std::function<void(const TskVsPartInfo* part)> predicate) {
    if (open()) {
      for (TSK_PNUM_T i = 0; i < volume_->getPartCount(); ++i) {
        std::unique_ptr<const TskVsPartInfo> part(volume_->getPart(i));
        if (part == nullptr) {
          continue;
        }
        // Windows requires min of 32GB of space, check for min number of NTFS
        // sectors
        if (part->getLen() <= 8388608) {
          continue;
        }
        predicate(part.get());
      }
    }
  }

  // Provide a path and read data.
  void readFile(const std::string& partition,
                std::unique_ptr<TskFsInfo>& fs,
                const std::string& file_path,
                std::vector<char>& file_contents);
  bool open();

 private:
  /// Has the device open been attempted.
  bool opened_{false};

  /// The result of the opened request.
  bool opened_result_{false};

  /// Image structure.
  std::shared_ptr<TskImgInfo> image_{nullptr};

  /// Volume structure.
  std::shared_ptr<TskVsInfo> volume_{nullptr};

  /// Filesystem path to the device node.
  std::string device_path_;
};
} // namespace osquery

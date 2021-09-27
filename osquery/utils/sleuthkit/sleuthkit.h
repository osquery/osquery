/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <boost/noncopyable.hpp>
#include <map>
#include <osquery/utils/conversions/tryto.h>
#include <set>
#include <tsk/libtsk.h>

#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>
namespace osquery {
class SleuthkitHelper : private boost::noncopyable {
 public:
  explicit SleuthkitHelper(const std::string& device_path)
      : image_(std::make_shared<TskImgInfo>()),
        volume_(std::make_shared<TskVsInfo>()),
        device_path_(device_path) {}

  /// Volume partition iterator.
  void partitions(
      std::function<void(const TskVsPartInfo* partition)> predicate) {
    if (open()) {
      for (TSK_PNUM_T i = 0; i < volume_->getPartCount(); ++i) {
        auto* part = volume_->getPart(i);
        if (part == nullptr) {
          continue;
        }
        predicate(part);
        delete part;
      }
    }
  }

  // Volume partition iterator for minimum Windows OS size.
  void partitionsMinOsSize(
      std::function<void(const TskVsPartInfo* part)> predicate) {
    if (open()) {
      for (TSK_PNUM_T i = 0; i < volume_->getPartCount(); ++i) {
        auto* part = volume_->getPart(i);
        if (part == nullptr) {
          continue;
        }
        // Windows requires min of 32GB of space, check for min number of NTFS
        // sectors
        if (part->getLen() <= 8388608) {
          delete part;
          continue;
        }
        predicate(part);
        delete part;
      }
    }
  }

  // Provide a path and read data.
  void readFile(const std::string& partition,
                TskFsInfo* fs,
                std::string reg_path,
                std::vector<char>& reg_contents);
  bool open();
  /*
  void inodes(
      const std::set<std::string>& inodes,
      TskFsInfo* fs,
      std::function<void(const std::string&, TskFsFile*, const std::string&)>
          predicate);

  /// Volume accessor, used for computing offsets using block/sector size.
  const std::shared_ptr<TskVsInfo>& getVolume() {
    return volume_;
  }

  /// Reset stack counting for directory iteration.
  void resetStack() {
    stack_ = 0;
    count_ = 0;
    std::set<std::string>().swap(loops_);
  }

 //private:
  /// Attempt to open the provided device image and volume.
  //bool open();
  */
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

  size_t stack_{0};
  size_t count_{0};
  std::set<std::string> loops_;
};
} // namespace osquery

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/utils/sleuthkit/sleuthkit.h>
#include <tsk/libtsk.h>

//#include <osquery/filesystem/filesystem.h>
//#include <osquery/hashing/hashing.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

bool SleuthkitHelper::open() {
  if (opened_) {
    return opened_result_;
  }

  // Attempt to open the device image.
  opened_ = true;
  auto status = image_->open(device_path_.c_str(), TSK_IMG_TYPE_DETECT, 0);
  if (status) {
    opened_result_ = false;
    return opened_result_;
  }

  // Attempt to open the device image volumn.
  status = volume_->open(&*image_, 0, TSK_VS_TYPE_DETECT);
  opened_result_ = (status == 0);
  return opened_result_;
}
/*
void SleuthkitHelper::inodes(
    const std::set<std::string>& inodes,
    TskFsInfo* fs,
    std::function<void(const std::string&, TskFsFile*, const std::string&)>
        predicate) {
  // Given a set of constraint inodes, convert each to an INUM.
  for (const auto& inode : inodes) {
    long int inode_meta = tryTo<long int>(inode, 10).takeOr(0l);
    auto* file = new TskFsFile();
    if (file->open(fs, file, static_cast<TSK_INUM_T>(inode_meta)) == 0) {
      // Attempt to get the meta and filesystem name for the inode.
      // If this inode is a file a valid meta/name structures are parsed.
      auto* meta = file->getMeta();
      if (meta != nullptr) {
        const auto* name = meta->getName2(0);
        if (name != nullptr) {
          auto path = std::string(name->getName());
          predicate(inode, file, path);
          delete name;
        }
        delete meta;
      }
    }
    delete file;
  }
}
*/
void SleuthkitHelper::readFile(const std::string& partition,
                               TskFsInfo* fs,
                               const std::string file_path,
                               std::vector<char>& file_contents) {
  if (stack_++ > 1024) {
    return;
  }
  TskFsFile* file_struct = nullptr;
  TskFsFile* new_file = new TskFsFile();
  auto result = new_file->open(fs, new_file, file_path.c_str());

  if (result) {
    delete new_file;
    return;
  } else {
    auto* meta = new_file->getMeta();
    TSK_OFF_T size = meta->getSize();
    auto* buffer = (char*)malloc(size);
    if (buffer != nullptr) {
      ssize_t chunk_size = 0;
      chunk_size = new_file->read(
          0, (char*)&buffer[0], size, TSK_FS_FILE_READ_FLAG_NONE);
      if (chunk_size == -1 || chunk_size != size) {
        free(buffer);
        delete meta;
        delete new_file;
        return;
      }
      std::vector<char> contents(buffer, buffer + size);
      file_contents = contents;
      delete meta;
      delete new_file;
      free(buffer);
      return;
    }
    free(buffer);

    delete new_file;
    delete meta;
    return;
  }
}
} // namespace osquery
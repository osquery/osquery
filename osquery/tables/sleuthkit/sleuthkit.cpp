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

#include <tsk/libtsk.h>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::map<TSK_FS_META_TYPE_ENUM, std::string> kTSKTypeNames{
    {TSK_FS_META_TYPE_REG, "regular"},
    {TSK_FS_META_TYPE_DIR, "directory"},
    {TSK_FS_META_TYPE_LNK, "symlink"},
    {TSK_FS_META_TYPE_BLK, "block"},
    {TSK_FS_META_TYPE_CHR, "character"},
    {TSK_FS_META_TYPE_FIFO, "fifo"},
    {TSK_FS_META_TYPE_SOCK, "socket"},
};

class DeviceHelper : private boost::noncopyable {
 public:
  explicit DeviceHelper(const std::string& device_path)
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

  void inodes(
      const std::set<std::string>& inodes,
      TskFsInfo* fs,
      std::function<void(const std::string&, TskFsFile*, const std::string&)>
          predicate);

  /// Provide a partition description for context and iterate from path.
  void generateFiles(const std::string& partition,
                     TskFsInfo* fs,
                     const std::string& path,
                     QueryData& results,
                     TSK_INUM_T inode = 0);

  /// Similar to generateFiles but only yield a row to results.
  void generateFile(const std::string& partition,
                    TskFsFile* file,
                    TskFsInfo* fs,
                    const std::string& path,
                    QueryData& results);

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

 private:
  /// Attempt to open the provided device image and volume.
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

  size_t stack_{0};
  size_t count_{0};
  std::set<std::string> loops_;
};

bool DeviceHelper::open() {
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

void DeviceHelper::inodes(
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

void DeviceHelper::generateFile(const std::string& partition,
                                TskFsFile* file,
                                TskFsInfo* fs,
                                const std::string& path,
                                QueryData& results) {
  Row r;
  r["device"] = device_path_;
  r["partition"] = partition;
  r["path"] = path;
  r["filename"] = fs::path(path).leaf().string();

  if (fs != nullptr) {
    r["block_size"] = BIGINT(fs->getBlockSize());
  }

  const auto* meta = file->getMeta();
  if (meta != nullptr) {
    r["inode"] = BIGINT(meta->getAddr());
    r["uid"] = BIGINT(meta->getUid());
    r["gid"] = BIGINT(meta->getGid());
    r["mode"] = SQL_TEXT(meta->getMode());
    r["size"] = BIGINT(meta->getSize());
    r["atime"] = BIGINT(meta->getATime());
    r["mtime"] = BIGINT(meta->getMTime());
    r["ctime"] = BIGINT(meta->getCrTime());
    r["hard_links"] = INTEGER(meta->getNLink());
    if (kTSKTypeNames.count(meta->getType())) {
      r["type"] = kTSKTypeNames.at(meta->getType());
    } else {
      r["type"] = "unknown";
    }
    delete meta;
  }
  results.push_back(r);
}

void DeviceHelper::generateFiles(const std::string& partition,
                                 TskFsInfo* fs,
                                 const std::string& path,
                                 QueryData& results,
                                 TSK_INUM_T inode) {
  if (stack_++ > 1024) {
    return;
  }

  auto* dir = new TskFsDir();
  if (dir->open(fs, ((inode == 0) ? fs->getRootINum() : inode))) {
    delete dir;
    return;
  }

  // Iterate through the directory.
  std::map<TSK_INUM_T, std::string> additional;
  for (size_t i = 0; i < dir->getSize(); i++) {
    if (count_++ > 1024 * 10) {
      break;
    }

    auto* file = dir->getFile(i);
    if (file == nullptr) {
      continue;
    }

    // Failure to access the file's metadata information.
    auto* meta = file->getMeta();
    if (meta == nullptr) {
      delete file;
      continue;
    }

    std::string leaf;
    auto* name = file->getName();
    if (name != nullptr) {
      leaf = (fs::path(path) / name->getName()).string();
    }

    if (meta->getType() == TSK_FS_META_TYPE_REG) {
      generateFile(partition, file, fs, leaf, results);
    } else if (meta->getType() == TSK_FS_META_TYPE_DIR) {
      if (name != nullptr && !TSK_FS_ISDOT(name->getName())) {
        additional[meta->getAddr()] = leaf;
      }
    }

    if (name != nullptr) {
      delete name;
    }
    delete meta;
    delete file;
  }
  delete dir;

  // If we are recursing.
  for (const auto& d : additional) {
    if (std::find(loops_.begin(), loops_.end(), d.second) == loops_.end()) {
      generateFiles(partition, fs, d.second, results, d.first);
      loops_.insert(d.second);
    }
  }
}

MultiHashes hashInode(TskFsFile* file) {
  Hash md5(HASH_TYPE_MD5);
  Hash sha1(HASH_TYPE_SHA1);
  Hash sha256(HASH_TYPE_SHA256);

  // We are guaranteed by the expected callsite to have a valid meta.
  auto* meta = file->getMeta();
  if (meta == nullptr) {
    return MultiHashes();
  }

  // Set a maximum 'chunk' or block size to 1 page or the file size.
  TSK_OFF_T size = meta->getSize();
  if (size == 0) {
    delete meta;
    return MultiHashes();
  }

  // Allocate some heap memory and iterate over reading a chunk and updating.
  auto buffer_size = (size < 4096) ? size : 4096;
  auto* buffer = (char*)malloc(buffer_size * sizeof(char));
  if (buffer != nullptr) {
    ssize_t chunk_size = 0;
    for (ssize_t offset = 0; offset < size; offset += chunk_size) {
      // Here max represents the local max requested bytes.
      auto max = (size - offset < buffer_size) ? (size - offset) : buffer_size;
      chunk_size =
          file->read(offset, buffer, max, (TSK_FS_FILE_READ_FLAG_ENUM)0U);
      if (chunk_size == -1 || chunk_size != max) {
        // Huge problem, either a read failed or didn't read the max size.
        free(buffer);
        delete meta;
        return MultiHashes();
      }

      md5.update(buffer, chunk_size);
      sha1.update(buffer, chunk_size);
      sha256.update(buffer, chunk_size);
    }
    free(buffer);
  }
  delete meta;

  // Convert the set of hashes into a device hashes transport.
  MultiHashes dhs = {};
  dhs.md5 = md5.digest();
  dhs.sha1 = sha1.digest();
  dhs.sha256 = sha256.digest();
  return dhs;
}

QueryData genDeviceHash(QueryContext& context) {
  QueryData results;

  auto devices = context.constraints["device"].getAll(EQUALS);
  // This table requires three columns to determine an action.
  auto parts = context.constraints["partition"].getAll(EQUALS);
  auto inodes = context.constraints["inode"].getAll(EQUALS);

  for (const auto& dev : devices) {
    // For each require device path, open a device helper that checks the
    // image, checks the volume, and allows partition iteration.
    DeviceHelper dh(dev);
    dh.partitions(([&results, &dev, &dh, &parts, &inodes](
        const TskVsPartInfo* part) {
      // The table also requires a partition for searching.
      auto address = std::to_string(part->getAddr());
      if (address != *parts.begin()) {
        // If this partition does not match the requested, continue.
        return;
      }

      auto* fs = new TskFsInfo();
      auto status = fs->open(part, TSK_FS_TYPE_DETECT);
      // Cannot retrieve file information without accessing the filesystem.
      if (status) {
        delete fs;
        return;
      }

      dh.inodes(inodes,
                fs,
                ([&results, &address, &dev](const std::string& inode,
                                            TskFsFile* file,
                                            const std::string& path) {
                  Row r;
                  r["device"] = dev;
                  r["partition"] = address;
                  r["inode"] = inode;

                  auto hashes = hashInode(file);
                  r["md5"] = std::move(hashes.md5);
                  r["sha1"] = std::move(hashes.sha1);
                  r["sha256"] = std::move(hashes.sha256);
                  results.push_back(r);
                }));
      delete fs;
    }));
  }

  return results;
}

QueryData genDeviceFile(QueryContext& context) {
  QueryData results;

  auto devices = context.constraints["device"].getAll(EQUALS);
  // This table requires two or more columns to determine an action.
  auto parts = context.constraints["partition"].getAll(EQUALS);
  // Additionally, paths or inodes can be used to search.
  auto paths = context.constraints["path"].getAll(EQUALS);
  auto inodes = context.constraints["inode"].getAll(EQUALS);

  if (devices.empty() || parts.size() != 1) {
    TLOG << "Device files require at least one device and a single partition";
    return {};
  }

  for (const auto& dev : devices) {
    // For each require device path, open a device helper that checks the
    // image, checks the volume, and allows partition iteration.
    DeviceHelper dh(dev);
    dh.partitions(([&results, &dh, &parts, &inodes, &paths](
                       const TskVsPartInfo* part) {
      // The table also requires a partition for searching.
      auto address = std::to_string(part->getAddr());
      if (address != *parts.begin()) {
        // If this partition does not match the requested, continue.
        return;
      }

      auto* fs = new TskFsInfo();
      auto status = fs->open(part, TSK_FS_TYPE_DETECT);
      // Cannot retrieve file information without accessing the filesystem.
      if (status) {
        delete fs;
        return;
      }

      // If no inodes or paths were provided as constraints assume a walk of
      // the partition was requested.
      if (inodes.empty() && paths.empty()) {
        dh.generateFiles(address, fs, "/", results);
        dh.resetStack();
      }

      // For each path the canonical name must be mapped to an inode address.
      for (const auto& path : paths) {
        auto* file = new TskFsFile();
        if (file->open(fs, file, path.c_str()) == 0) {
          dh.generateFile(address, file, fs, path, results);
        }
        delete file;
      }

      dh.inodes(inodes,
                fs,
                ([&results, &address, &dh, &fs](const std::string& inode,
                                                TskFsFile* file,
                                                const std::string& path) {
                  dh.generateFile(address, file, fs, path, results);
                }));
      delete fs;
    }));
  }

  return results;
}

QueryData genDevicePartitions(QueryContext& context) {
  QueryData results;

  auto devices = context.constraints["device"].getAll(EQUALS);
  for (const auto& dev : devices) {
    DeviceHelper dh(dev);
    dh.partitions(([&results, &dev, &dh](const TskVsPartInfo* part) {
      Row r;
      r["device"] = dev;
      r["partition"] = std::to_string(part->getAddr());

      const auto* desc = part->getDesc();
      if (desc != nullptr) {
        r["label"] = desc;
      }

      r["flags"] = "0";
      if (part->getFlags() & TSK_VS_PART_FLAG_META) {
        r["type"] = "meta";
      } else if (part->getFlags() & TSK_VS_PART_FLAG_UNALLOC) {
        r["type"] = "unallocated";
      } else {
        r["type"] = "normal";
      }

      auto* fs = new TskFsInfo();
      auto status = fs->open(part, TSK_FS_TYPE_DETECT);
      if (status) {
        r["offset"] = BIGINT(part->getStart() * dh.getVolume()->getBlockSize());
        r["blocks_size"] = BIGINT(dh.getVolume()->getBlockSize());
        r["blocks"] = BIGINT(part->getLen());
        r["inodes"] = "-1";
        r["flags"] = INTEGER(part->getFlags());
      } else {
        // If there is a filesystem in this partition we can use the name/type
        // of the filesystem as the "type".
        r["type"] = TskFsInfo::typeToName(fs->getFsType());
        r["flags"] = INTEGER(fs->getFlags());
        r["offset"] = BIGINT(fs->getOffset());
        r["blocks_size"] = BIGINT(fs->getBlockSize());
        r["blocks"] = BIGINT(fs->getBlockCount());
        r["inodes"] = BIGINT(fs->getINumCount());
      }
      delete fs;
      results.push_back(r);
    }));
  }

  return results;
}
}
}

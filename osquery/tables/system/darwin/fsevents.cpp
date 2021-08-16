/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <string>
#include <vector>

#include <fstream>

namespace osquery {
namespace tables {

struct FsEventData {
  int sig;
  int padding;
  int stream_size;
};

const int kHeaderSize = 12;
const int kDiskLoggerV2 = 0x444c5332;
const int kDiskLoggerV1 = 0x444c5331;
const std::string kBigSurPath = "/System/Volumes/Data/.fseventsd/";
const std::string kOtherVolumes = "/Volumes/";
const std::string kOldPath = "/.fseventsd";

const std::map<int, std::string> kFlags{{0x0, "None"},
                                        {0x01, "Created"},
                                        {0x02, "Removed"},
                                        {0x04, "InodeMetadataModified"},
                                        {0x08, "Renamed"},
                                        {0x10, "Modified"},
                                        {0x20, "Exchange"},
                                        {0x40, "FinderInfoModified"},
                                        {0x80, "DirectoryCreated"},
                                        {0x100, "PermissionChanged"},
                                        {0x200, "ExtendedAttributeModified"},
                                        {0x400, "ExtenedAttributeRemoved"},
                                        {0x800, "DocumentCreated"},
                                        {0x1000, "DocumentRevision"},
                                        {0x2000, "UnmountPending"},
                                        {0x4000, "ItemCloned"},
                                        {0x10000, "NotificationClone"},
                                        {0x20000, "ItemTruncated"},
                                        {0x40000, "DirectoryEvent"},
                                        {0x80000, "LastHardLinkRemoved"},
                                        {0x100000, "IsHardLink"},
                                        {0x400000, "IsSymbolicLink"},
                                        {0x800000, "IsFile"},
                                        {0x1000000, "IsDirectory"},
                                        {0x2000000, "Mount"},
                                        {0x4000000, "Unmount"},
                                        {0x20000000, "EndOfTransaction"}};

int parseFsEvent(const std::vector<char>& fsevent_data,
                 const int& stream_size,
                 const int& sig,
                 const std::string& filename,
                 const unsigned long& offset,
                 QueryData& results) {
  int size = kHeaderSize;
  while (size < stream_size) {
    Row r;
    std::string path(fsevent_data.begin() + size + offset,
                     fsevent_data.begin() + stream_size + size + offset);
    size_t path_length = strnlen(path.c_str(), stream_size);
    std::string file_path = path.substr(0, path_length);
    long long event_id = 0;
    memcpy(&event_id,
           &fsevent_data[file_path.size() + 1 + size + offset],
           sizeof(event_id));
    int flags = 0;
    std::string all_flags;
    memcpy(
        &flags,
        &fsevent_data[file_path.size() + 1 + sizeof(event_id) + size + offset],
        sizeof(flags));
    for (const auto& flag : kFlags) {
      if (flags & flag.first) {
        all_flags += flag.second + ",";
      }
    }
    all_flags.pop_back();
    if (sig == kDiskLoggerV1) {
      size += path_length + 1 + sizeof(event_id) + sizeof(flags);
      r["path"] = "/" + file_path;
      r["event_id"] = BIGINT(event_id);
      r["source"] = filename;
      r["flags"] = all_flags;
      results.push_back(r);
      continue;
    }
    long long node_id = 0;
    memcpy(&node_id,
           &fsevent_data[file_path.size() + 1 + sizeof(event_id) +
                         sizeof(flags) + size + offset],
           sizeof(node_id));
    size +=
        path_length + 1 + sizeof(node_id) + sizeof(event_id) + sizeof(flags);
    r["path"] = "/" + file_path;
    r["event_id"] = BIGINT(event_id);
    r["node_id"] = BIGINT(node_id);
    r["source"] = filename;
    r["flags"] = all_flags;
    results.push_back(r);
  }

  return size;
}

void parseFsEventData(const std::vector<char>& fsevent_data,
                      const std::string& filename,
                      QueryData& results) {
  FsEventData event_data;

  unsigned long fsevent_size = 0;
  while (fsevent_size < fsevent_data.size()) {
    // Get header data, contains size of stream
    memcpy(&event_data, &fsevent_data[fsevent_size], kHeaderSize);
    if ((event_data.sig == kDiskLoggerV2) ||
        (event_data.sig == kDiskLoggerV1)) {
      int size = parseFsEvent(fsevent_data,
                              event_data.stream_size,
                              event_data.sig,
                              filename,
                              fsevent_size,
                              results);
      fsevent_size += size;

    } else {
      LOG(WARNING) << "Unknown FS Event signature: " << event_data.sig;
      break;
    }
  }
}

void parseEvents(const std::string& file, QueryData& results) {
  std::ifstream compressed_file(file,
                                std::ios_base::in | std::ios_base::binary);
  try {
    boost::iostreams::filtering_stream<boost::iostreams::input> decompress;
    decompress.push(boost::iostreams::gzip_decompressor());
    decompress.push(compressed_file);

    std::vector<char> decompress_data(
        (std::istreambuf_iterator<char>(decompress)),
        (std::istreambuf_iterator<char>()));
    compressed_file.close();

    parseFsEventData(decompress_data, file, results);
  } catch (const std::exception& err) {
    LOG(WARNING) << "Failed to parse fsevent file, need to be root: "
                 << err.what();
  }
}

QueryData genFsevents(QueryContext& context) {
  QueryData results;
  std::vector<std::string> fsevents_files;
  // Get FS Events in Big Sur
  listFilesInDirectory(kBigSurPath, fsevents_files);
  for (const auto& file : fsevents_files) {
    if (file.find("fseventsd-uuid", 0) != std::string::npos) {
      continue;
    }
    parseEvents(file, results);
  }
  fsevents_files.clear();

  // Get FS Events for connected drives (Only macOS formatted drives will have
  // fseventsd data)
  listDirectoriesInDirectory(kOtherVolumes, fsevents_files);
  for (const auto& volumes : fsevents_files) {
    boost::filesystem::path path = volumes;
    boost::system::error_code ec;
    if (!boost::filesystem::is_directory(path, ec)) {
      continue;
    }
    std::vector<std::string> fsevents_volumes;
    std::string full_path = volumes + "/.fseventsd";
    listFilesInDirectory(full_path, fsevents_volumes);
    for (const auto& file : fsevents_volumes) {
      if (file.find("fseventsd-uuid", 0) != std::string::npos) {
        continue;
      }
      parseEvents(file, results);
    }
  }
  fsevents_files.clear();

  // Get FS Event data on older macOS systems
  listFilesInDirectory(kOldPath, fsevents_files);
  for (const auto& file : fsevents_files) {
    if (file.find("fseventsd-uuid", 0) != std::string::npos) {
      continue;
    }
    parseEvents(file, results);
  }
  return results;
}
} // namespace tables
} // namespace osquery

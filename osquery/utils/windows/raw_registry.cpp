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

#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <osquery/utils/windows/raw_registry.h>
#include <tsk/libtsk.h>

#include <iomanip>
#include <sstream>
#include <vector>

namespace osquery {

struct RegHeader {
  int sig;
  int primary_num;
  int secondary_num;
  char modified_time[8];
  int major_version;
  int minor_version;
  int file_type;
  int file_format;
  int root_key_offset;
  int hive_bin_size;
  int clustering_factor;
  char unknown[64];
  char unknown2[396];
  int checksum;
  char reserved[3576];
  int boot_type;
  int boot_recover;
};

struct RegHiveBin {
  int sig;
  int offset;
  int size;
  int reserved;
  int64_t timestamp;
  int unknown;
};

struct RegValueKey {
  short sig;
  short value_name_size;
  int data_size;
  int data_offset;
  int data_type;
  short flags;
  short unknown;
};

struct RegLeafHash {
  short sig;
  short num_elements;
};

struct RegBigData {
  short sig;
  short num_segments;
  int block_offset;
};

struct RegSecurityKey {
  short sig;
  short unknown;
  int flink;
  int blink;
  int ref_count;
  int security_descriptor_size;
};

const int kheader_size = 4096;

// Paritally taken from Sleuthkit table
class DeviceHelper : private boost::noncopyable {
 public:
  explicit DeviceHelper(const std::string& device_path)
      : image_(std::make_shared<TskImgInfo>()),
        volume_(std::make_shared<TskVsInfo>()),
        device_path_(device_path) {}

  /// Volume partition iterator.
  void partitions(std::function<void(const TskVsPartInfo* part)> predicate) {
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

  /// Provide a partition description for context and iterate from path.
  void generateFiles(const std::string& partition,
                     TskFsInfo* fs,
                     const std::string& path,
                     std::string reg_path,
                     std::vector<char>& reg_contents,
                     TSK_INUM_T inode = 0);

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
};

bool DeviceHelper::open() {
  if (opened_) {
    return opened_result_;
  }

  // Attempt to open the device image.
  opened_result_ = true;
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

void DeviceHelper::generateFiles(const std::string& partition,
                                 TskFsInfo* fs,
                                 const std::string& path,
                                 const std::string reg_path,
                                 std::vector<char>& reg_contents,
                                 TSK_INUM_T inode) {
  if (stack_++ > 1024) {
    return;
  }
  TskFsFile* file_struct = nullptr;
  TskFsFile* new_file = new TskFsFile();
  auto result = new_file->open(fs, new_file, reg_path.c_str());

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
      std::vector<char> reg(buffer, buffer + size);
      reg_contents = reg;
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

std::vector<char> rawReadRegistry(const std::string& reg_path,
                                  const std::string& drive_path) {
  DeviceHelper dh(drive_path);
  std::vector<char> reg_contents;
  dh.partitions(([&dh, &reg_path, &reg_contents](const TskVsPartInfo* part) {
    if (part->getFlags() != TSK_VS_PART_FLAG_ALLOC) {
      return;
    }

    std::string address = std::to_string(part->getAddr());
    auto* fs = new TskFsInfo();
    TSK_OFF_T offset = 0;
    auto status = fs->open(part, TSK_FS_TYPE_DETECT);
    // Cannot retrieve file information without accessing the filesystem.
    if (status) {
      delete fs;
      return;
    }

    dh.generateFiles(address, fs, "/", reg_path, reg_contents);
    if (reg_contents.size() > 0) {
      delete fs;
      return;
    }
    delete fs;
  }));
  return reg_contents;
}

RegHiveBin parseHiveBin(const std::vector<char>& reg_contents,
                        const int& offset) {
  RegHiveBin hive_bin;
  const int hive_bin_size = 32;
  memcpy(&hive_bin, &reg_contents[offset], hive_bin_size);
  return hive_bin;
}

void parseHiveLeafHash(const std::vector<char>& reg_contents,
                       int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key) {
  RegLeafHash leaf_hash;
  int leaf_hash_min_size = 4;
  memcpy(&leaf_hash, &reg_contents[offset], leaf_hash_min_size);
  int elements = 0;
  int elememnt_offset = 0;
  int named_key_offset = 0;

  while (elements < leaf_hash.num_elements) {
    memcpy(&named_key_offset,
           &reg_contents[offset + leaf_hash_min_size + elememnt_offset],
           sizeof(named_key_offset));
    elements++;
    elememnt_offset += 8;
    parseHiveCell(reg_contents, named_key_offset, raw_reg, key_path, name_key);
  }
}

void parseHiveLeafIndex(const std::vector<char>& reg_contents,
                        int& offset,
                        std::vector<RegTableData>& raw_reg,
                        std::vector<std::string>& key_path,
                        const RegNameKey& name_key) {
  RegLeafHash leaf_index;
  int leaf_index_min_size = 4;
  memcpy(&leaf_index, &reg_contents[offset], leaf_index_min_size);
  int elements = 0;
  int elememnt_offset = 0;
  int named_key_offset = 0;
  while (elements < leaf_index.num_elements) {
    memcpy(&named_key_offset,
           &reg_contents[offset + leaf_index_min_size + elememnt_offset],
           sizeof(named_key_offset));
    elements++;
    elememnt_offset += 4;
    parseHiveCell(reg_contents, named_key_offset, raw_reg, key_path, name_key);
  }
}

void parseValueKeyList(const std::vector<char>& reg_contents,
                       const int& num_values,
                       const int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key) {
  int value_entries = 0;
  int unknown = 4;
  int value_list_offset = 0;
  while (value_entries < num_values) {
    int value_offset = 0;
    memcpy(&value_offset,
           &reg_contents[offset + kheader_size + unknown + value_list_offset],
           sizeof(value_offset));
    value_list_offset += 4;
    parseHiveCell(reg_contents, value_offset, raw_reg, key_path, name_key);
    value_entries++;
  }
}

void parseNameKey(const std::vector<char>& reg_contents,
                  int& offset,
                  std::vector<RegTableData>& raw_reg,
                  std::vector<std::string>& key_path) {
  RegNameKey name_key;
  const int name_key_min_size = 76;
  memcpy(&name_key, &reg_contents[offset], name_key_min_size);
  std::string key_name(reg_contents.begin() + offset + name_key_min_size,
                       reg_contents.begin() + offset + name_key_min_size +
                           name_key.key_name_size);
  key_path.push_back(key_name);

  // Check if Security Key exists
  if (name_key.security_key_offset != -1) {
    parseHiveCell(reg_contents,
                  name_key.security_key_offset,
                  raw_reg,
                  key_path,
                  name_key);
  }

  if (name_key.number_values == 0) {
    // Now have all the data to build the table (key has no values)
    RegTableData reg_table;
    reg_table.key = osquery::join(key_path, "\\");
    reg_table.key_path = osquery::join(key_path, "\\");
    reg_table.key_type = "subkey";
    reg_table.modified_time = filetimeToUnixtime(name_key.timestamp);
    raw_reg.push_back(reg_table);
  } else {
    parseValueKeyList(reg_contents,
                      name_key.number_values,
                      name_key.value_list_offset,
                      raw_reg,
                      key_path,
                      name_key);
  }
  parseHiveCell(
      reg_contents, name_key.sub_key_list_offset, raw_reg, key_path, name_key);
  key_path.pop_back();
}

// Get the data associated with Registry value key
std::string parseDataValue(const std::vector<char>& reg_contents,
                           const int& offset,
                           const int& size,
                           const std::string& reg_type) {
  const int data_size = size + 1;
  int data_size_and_slack = 0;
  // The raw registry data value can contain remnants of previous entries in
  // slack space, currently ignoring slack data for now
  memcpy(&data_size_and_slack,
         &reg_contents[offset + kheader_size],
         sizeof(data_size_and_slack));
  std::string data;
  if (data_size == 0) {
    return data;
  }

  auto data_buff = std::make_unique<BYTE[]>(data_size);
  // Format data base on Registry Type (similar to the existing api registry
  // table)
  if (reg_type == "REG_SZ") {
    memcpy(data_buff.get(),
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    data = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
  } else if (reg_type == "REG_BINARY" || reg_type == "REG_RESOURCE_LIST" ||
             reg_type == "REG_FULL_RESOURCE_DESCRIPTOR" ||
             reg_type == "REG_RESOURCE_REQUIREMENTS_LIST" ||
             reg_type == "REG_TYPE_UNKNOWN" || reg_type == "REG_NONE") {
    memcpy(data_buff.get(),
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           data_size);
    std::vector<char> reg_binary;
    for (size_t j = 0; j < data_size; j++) {
      reg_binary.push_back((char)data_buff[j]);
    }

    boost::algorithm::hex(
        reg_binary.begin(), reg_binary.end(), std::back_inserter(data));
  } else if (reg_type == "REG_DWORD") {
    int reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(reg_dword);
  } else if (reg_type == "REG_DWORD_BIG_ENDIAN") {
    int reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(_byteswap_ulong(reg_dword));
  } else if (reg_type == "REG_LINK") {
    memcpy(data_buff.get(),
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    data = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
  } else if (reg_type == "REG_EXPAND_SZ") {
    memcpy(data_buff.get(),
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    data = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
  } else if (reg_type == "REG_QWORD") {
    unsigned long long reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(reg_dword);
  } else if (reg_type == "REG_MULTI_SZ") {
    memcpy(data_buff.get(),
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    auto p = reinterpret_cast<wchar_t*>(data_buff.get());
    std::vector<std::string> reg_multi_sz;
    size_t string_size = 0;
    while (*p != 0x00) {
      std::string s = wstringToString(p);
      p += wcslen(p) + 1;
      string_size += s.size();
      reg_multi_sz.push_back(s);
      // Since we convert to normal string, our size is cut in half and the wide
      // string end-of-char is gone
      if (string_size * 2 == data_size - 3) {
        break;
      }
    }
    data = osquery::join(reg_multi_sz, ",");
  } else if (reg_type == "REG_FILETIME") {
    FILETIME file_time;
    memcpy(&file_time,
           &reg_contents[offset + kheader_size + sizeof(data_size_and_slack)],
           sizeof(file_time));
    data = std::to_string(filetimeToUnixtime(file_time));
  }
  SecureZeroMemory(data_buff.get(), data_size);
  return data;
}

// Get the Registry value keys
void parseValueKey(const std::vector<char>& reg_contents,
                   const int& hive_bin_offset,
                   std::vector<RegTableData>& raw_reg,
                   std::vector<std::string>& key_path,
                   const RegNameKey& name_key) {
  RegValueKey value_key;
  const int value_min_size = 20;
  std::map<int, std::string> reg_types{{0, "REG_NONE"},
                                       {1, "REG_SZ"},
                                       {2, "REG_EXPAND_SZ"},
                                       {3, "REG_BINARY"},
                                       {4, "REG_DWORD"},
                                       {5, "REG_DWORD_BIG_ENDIAN"},
                                       {6, "REG_LINK"},
                                       {7, "REG_MULTI_SZ"},
                                       {8, "REG_RESOURCE_LIST"},
                                       {9, "REG_FULL_RESOURCE_DESCRIPTOR"},
                                       {10, "REG_RESOURCE_REQUIREMENTS_LIST"},
                                       {11, "REG_QWORD"},
                                       {16, "REG_FILETIME"}};
  memcpy(&value_key, &reg_contents[hive_bin_offset], value_min_size);
  std::string reg_type;
  try {
    reg_type = reg_types.at(value_key.data_type);
  } catch (std::out_of_range) {
    reg_type = "REG_TYPE_UNKNOWN"; // Some Registry key entries dont have a
                                   // known type (seen mainly in SAM hive)
  }
  std::string name;
  if (value_key.value_name_size == 0) {
    name = "(default)";
  } else {
    // Name is in ASCII otherwise its UTF16
    if (value_key.flags == 1) {
      std::string reg_value_name(
          reg_contents.begin() + value_min_size + hive_bin_offset,
          reg_contents.begin() + value_min_size + hive_bin_offset +
              value_key.value_name_size);
      name = reg_value_name;
    } else {
      auto data_buff = std::make_unique<BYTE[]>(value_key.value_name_size);
      memcpy(data_buff.get(),
             &reg_contents[hive_bin_offset + value_min_size],
             value_key.value_name_size);
      data_buff[value_key.value_name_size - 1] = 0x00;
      name = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
    }
  }

  std::string data;
  // Value key data exists in Value key (the value_key.data.offset actually
  // contains the data) if the data is greater than 0x80000000. Basically if the
  // data is 4 bytes or less its stored in the Value key
  if ((value_key.data_size >= 0x80000000) && (value_key.data_size < 0)) {
    int size = value_key.data_size - 0x80000000;
    if (size == 4) {
      data = std::to_string(value_key.data_offset);
    } else if (size == 2) {
      data = std::to_string((value_key.data_offset & 0x0000ffff));
    } else if (size == 1) {
      data = std::to_string((value_key.data_offset >> (8 * 3) & 0xff));
    } else {
      data = "null";
    }
  } else {
    data = parseDataValue(
        reg_contents, value_key.data_offset, value_key.data_size, reg_type);
  }
  // Now have all the data to build the table
  RegTableData reg_table;
  reg_table.key = osquery::join(key_path, "\\");
  key_path.push_back(name);
  reg_table.key_path = osquery::join(key_path, "\\");
  key_path.pop_back();
  reg_table.key_name = name;
  reg_table.key_type = reg_type;
  reg_table.key_data = data;
  reg_table.modified_time = filetimeToUnixtime(name_key.timestamp);
  raw_reg.push_back(reg_table);
}

// Registry key cells (version 1.3+) that contain more than 16344 bytes have Big
// data cell (DB)
void parseHiveBigData(const std::vector<char>& reg_contents,
                      const int& offset,
                      std::vector<RegTableData>& raw_reg,
                      std::vector<std::string>& key_path,
                      const RegNameKey& name_key) {
  RegBigData big_data;
  const int big_data_min_size = 8;
  memcpy(&big_data, &reg_contents[offset], big_data_min_size);
  int segments = 0;
  int segment_offset = 0;
  // Big data segments contain offset to value key offset
  while (segments < big_data.num_segments) {
    int vk_offset = 0;
    memcpy(&vk_offset,
           &reg_contents[big_data.block_offset + segment_offset],
           sizeof(int));
    parseHiveCell(reg_contents, vk_offset, raw_reg, key_path, name_key);
    segment_offset += 4;
    segments++;
  }
}

// Complex Registry key that contains Access Control Entries (ACE), permissions
// for registry keys
void parseHiveSecurityKey(const std::vector<char>& reg_contents,
                          const int& offset,
                          std::vector<RegTableData>& raw_reg,
                          std::vector<std::string>& key_path,
                          const RegNameKey& name_key) {
  const int security_key_min_size = 20;
  RegSecurityKey security_key;
  memcpy(&security_key, &reg_contents[offset], security_key_min_size);
  // Security descriptor contains all the ACE metadata
  std::vector<char> security_descriptor(
      reg_contents.begin() + offset + security_key_min_size,
      reg_contents.begin() + offset + security_key_min_size +
          security_key.security_descriptor_size);
}

// Function to handle all the Registry cell types
void parseHiveCell(const std::vector<char>& reg_contents,
                   const int& hive_offset,
                   std::vector<RegTableData>& raw_reg,
                   std::vector<std::string>& key_path,
                   const RegNameKey& name_key) {
  // Offset of negative one (0xffffffff) means an empty subkey
  if (hive_offset == -1) {
    return;
  }
  int cell_size = 0;

  // Always add 4096/0x1000 (header size) to any registry offset
  int offset = hive_offset + kheader_size;
  // Registry key types
  const short vk = 27510; // value key
  const short nk = 27502; // name key
  const short sk = 27507; // security key
  const short lh = 26732; // leaf hash
  const short li = 26988; // leaf index
  const short db = 25188; // big data
  const short ri = 26994; // root index
  const short lf = 26220; // fast leaf
  memcpy(&cell_size, &reg_contents[offset], sizeof(cell_size));
  // Allocated cells have negative values, if the value is greater than zero its
  // unallocated
  if (cell_size > 0) {
    return;
  }
  unsigned short cell_type = 0;
  memcpy(
      &cell_type, &reg_contents[offset + sizeof(cell_size)], sizeof(cell_type));

  if (cell_type == nk) {
    offset += sizeof(cell_size);
    parseNameKey(reg_contents, offset, raw_reg, key_path);
  } else if (cell_type == vk) {
    offset += sizeof(cell_size);
    parseValueKey(reg_contents, offset, raw_reg, key_path, name_key);
  } else if (cell_type == sk) {
    offset += sizeof(cell_size);
    parseHiveSecurityKey(reg_contents, offset, raw_reg, key_path, name_key);
  } else if (cell_type == db) {
    offset += sizeof(cell_size);
    parseHiveBigData(reg_contents, offset, raw_reg, key_path, name_key);
  } else if (cell_type == lf) {
    offset += sizeof(cell_size);
    parseHiveLeafHash(reg_contents, offset, raw_reg, key_path, name_key);
  } else if (cell_type == li) {
    offset += sizeof(cell_size);
    parseHiveLeafIndex(reg_contents, offset, raw_reg, key_path, name_key);
  } else if (cell_type == lh) {
    offset += sizeof(cell_size);
    parseHiveLeafHash(reg_contents, offset, raw_reg, key_path, name_key);
  } else if (cell_type == ri) {
    offset += sizeof(cell_size);
    parseHiveLeafIndex(reg_contents, offset, raw_reg, key_path, name_key);
  }
}

std::vector<RegTableData> buildRegistry(std::vector<char>& reg_contents) {
  std::vector<RegTableData> raw_reg;
  RegHeader header;

  memcpy(&header, &reg_contents[0], kheader_size);
  if (header.sig != 0x66676572) {
    LOG(WARNING) << "Not a registry file, expected sig 'regf'";
    return raw_reg;
  }
  if (header.major_version == 1 && header.minor_version < 2) {
    LOG(WARNING)
        << "Unsupported Registry version, expected version 1.2 or higher, got: "
        << header.major_version << "." << header.minor_version;
    return raw_reg;
  }
  const int hive_header_size = 32;

  int offset = hive_header_size;
  std::vector<std::string> key_path;
  RegNameKey name_key;
  // From the first Registry Hive cell we can parse and build the whole registry
  // tree
  parseHiveCell(reg_contents, offset, raw_reg, key_path, name_key);
  return raw_reg;
}

std::vector<RegTableData> rawRegistry(const std::string& reg_path,
                                      const std::string& drive_path) {
  std::vector<RegTableData> raw_reg;
  std::vector<char> reg_contents = rawReadRegistry(reg_path, drive_path);
  if (reg_contents.size() == 0) {
    LOG(INFO) << "Failed to read registry contents, read zero bytes: "
              << reg_path;
    return raw_reg;
  }
  if (reg_contents.size() < kheader_size) {
    LOG(WARNING) << "Registry file too small: " << reg_path;
    return raw_reg;
  }
  raw_reg = buildRegistry(reg_contents);
  return raw_reg;
}
} // namespace osquery
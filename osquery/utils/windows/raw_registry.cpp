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
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/sleuthkit/sleuthkit.h>
#include <osquery/utils/windows/raw_registry.h>

#include <tsk/libtsk.h>

#include <iomanip>
#include <sstream>
#include <vector>

#include <iostream>
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

struct RegLeafIndex {
  short sig;
  short num_elements;
};

struct RegRootIndex {
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
const int kmax_registry_depth = 512;

// Convert args to correct format (sleuthkit expects forward
// slashes and no drive letter)
void cleanRegPath(std::string& reg_path) {
  size_t path = reg_path.find(":", 0);
  if (path != std::string::npos) {
    reg_path = reg_path.substr(path + 2);
  }
  std::replace(reg_path.begin(), reg_path.end(), '\\', '/');
}

// Keep track of registry offsets in case there is a infinite offset loop
// (should not exist in legit registry files)
ExpectedOffsetTracker checkOffsetTracker(const std::size_t& reg_contents_size,
                                         const int& offset,
                                         std::vector<int>& offset_tracker) {
  if (offset_tracker.size() > reg_contents_size) {
    return ExpectedOffsetTracker::failure(
        ConversionError::InvalidArgument,
        "More offsets than registry contents");
  }
  offset_tracker.push_back(offset);
  return ExpectedOffsetTracker::success(offset_tracker);
}

// Check all offsets to compare with registry contents size. Offsets should
// always be smaller
ExpectedOffset checkOffset(const std::size_t& reg_contents_size,
                           const int& offset) {
  if (offset > reg_contents_size) {
    LOG(INFO) << "Offset is greater than Registry contents, offset: " << offset
              << " registry contents: " << reg_contents_size;
    return ExpectedOffset::failure(ConversionError::InvalidArgument,
                                   "Offset is greater than Registry contents");
  }

  return ExpectedOffset::success(true);
}

// Read Registry file using sleuthkit, using registry path and physical drive
// (ex: \\.\PhysicalDrive0)
std::vector<char> rawReadRegistry(const std::string& reg_path,
                                  const std::string& drive_path) {
  SleuthkitHelper dh(drive_path);
  std::vector<char> reg_contents;
  // Only search for registry file on partitions that meet Windows OS storage
  // requirements
  dh.partitionsMinOsSize(
      ([&dh, &reg_path, &reg_contents](const TskVsPartInfo* part) {
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
        // Read the registry file
        dh.readFile(address, fs, reg_path, reg_contents);
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
  RegHiveBin hive_bin{};
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return hive_bin;
  }

  const int hive_bin_size = 32;
  memcpy(&hive_bin, &reg_contents[offset], hive_bin_size);
  return hive_bin;
}

// Parse a Leaf Hash Cell, contains a list of offsets to other name key cells
void parseHiveLeafHash(const std::vector<char>& reg_contents,
                       int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       std::vector<int>& offset_tracker,
                       int& depth_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  RegLeafHash leaf_hash;
  int leaf_hash_min_size = 4;
  memcpy(&leaf_hash, &reg_contents[offset], leaf_hash_min_size);
  const short lh = 26732; // leaf hash
  if (leaf_hash.sig != lh) {
    return;
  }
  int elements = 0;
  int element_offset = 0;
  int named_key_offset = 0;

  // Loop through all the number of offsets. Compare offset sizes
  while (elements < leaf_hash.num_elements) {
    expected = checkOffset(reg_contents.size(),
                           offset + leaf_hash_min_size + element_offset);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    memcpy(&named_key_offset,
           &reg_contents[offset + leaf_hash_min_size + element_offset],
           sizeof(named_key_offset));

    elements++;
    element_offset += 8;
    // Parse Name key at offset
    parseNameKey(reg_contents,
                 named_key_offset,
                 raw_reg,
                 key_path,
                 offset_tracker,
                 depth_tracker);
  }
}

// Parse a Leaf Index Cell, contains a list of offsets to other name key cells
void parseHiveLeafIndex(const std::vector<char>& reg_contents,
                        int& offset,
                        std::vector<RegTableData>& raw_reg,
                        std::vector<std::string>& key_path,
                        std::vector<int>& offset_tracker,
                        int& depth_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  RegLeafIndex leaf_index;
  int leaf_index_min_size = 4;
  memcpy(&leaf_index, &reg_contents[offset], leaf_index_min_size);
  const short li = 26988; // leaf index
  if (leaf_index.sig != li) {
    return;
  }
  int elements = 0;
  int element_offset = 0;
  int named_key_offset = 0;

  // Loop through list of offsets. Compare offset size and check for duplicates
  while (elements < leaf_index.num_elements) {
    expected = checkOffset(reg_contents.size(),
                           offset + leaf_index_min_size + element_offset);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    memcpy(&named_key_offset,
           &reg_contents[offset + leaf_index_min_size + element_offset],
           sizeof(named_key_offset));
    elements++;
    element_offset += 4;

    // Parse name key at offset
    parseNameKey(reg_contents,
                 named_key_offset,
                 raw_reg,
                 key_path,
                 offset_tracker,
                 depth_tracker);
  }
}

// Parse a Root Index Cell, contains a list of offsets to other offset lists
void parseHiveRootIndex(const std::vector<char>& reg_contents,
                        const int& offset,
                        std::vector<RegTableData>& raw_reg,
                        std::vector<std::string>& key_path,
                        std::vector<int>& offset_tracker,
                        int& depth_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  RegRootIndex root_index;
  int root_index_min_size = 4;
  memcpy(&root_index, &reg_contents[offset], root_index_min_size);

  int elements = 0;
  int element_offset = 0;
  int list_offset = 0;

  RegHeader header;
  memcpy(&header, &reg_contents[0], kheader_size);
  // Loop through list of offsets. Compare offset size and check for duplicates
  while (elements < root_index.num_elements) {
    expected = checkOffset(reg_contents.size(),
                           offset + root_index_min_size + element_offset);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    memcpy(&list_offset,
           &reg_contents[offset + root_index_min_size + element_offset],
           sizeof(list_offset));
    elements++;
    element_offset += 4;
    list_offset += 4;
    if (header.minor_version == 3) {
      parseHiveLeafIndex(reg_contents,
                         list_offset,
                         raw_reg,
                         key_path,
                         offset_tracker,
                         depth_tracker);
    } else {
      parseHiveLeafHash(reg_contents,
                        list_offset,
                        raw_reg,
                        key_path,
                        offset_tracker,
                        depth_tracker);
    }
  }
}

// Parse list of Value Keys
void parseValueKeyList(const std::vector<char>& reg_contents,
                       const int& num_values,
                       const int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key) {
  int value_entries = 0;
  int unknown = 4;
  int value_list_offset = 0;

  // Loop through number of Value Keys. Compare offset and check for duplicates
  while (value_entries < num_values) {
    auto expected =
        checkOffset(reg_contents.size(),
                    offset + kheader_size + unknown + value_list_offset);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    int value_offset = 0;
    memcpy(&value_offset,
           &reg_contents[offset + kheader_size + unknown + value_list_offset],
           sizeof(value_offset));
    value_list_offset += 4;

    // Parse Value key at offset
    parseValueKey(reg_contents, value_offset, raw_reg, key_path, name_key);
    value_entries++;
  }
}

// Parse Registry Key Name and check for name key metadata
void parseNameKey(const std::vector<char>& reg_contents,
                  int& reg_offset,
                  std::vector<RegTableData>& raw_reg,
                  std::vector<std::string>& key_path,
                  std::vector<int>& offset_tracker,
                  int& depth_tracker) {
  // Registry has max depth of 512 nested sub keys
  if (depth_tracker > kmax_registry_depth) {
    return;
  }
  depth_tracker++;
  // Offset of negative one (0xffffffff) means an empty subkey
  if (reg_offset == -1) {
    return;
  }
  // Always add 4096/0x1000 (header size) to any registry offset
  int offset = reg_offset + kheader_size;

  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  auto expected_tracker =
      checkOffsetTracker(reg_contents.size(), offset, offset_tracker);
  if (expected_tracker.isError()) {
    LOG(INFO) << expected_tracker.getError();
    return;
  }

  offset_tracker = expected_tracker.take();
  int cell_size = 0;
  memcpy(&cell_size, &reg_contents[offset], sizeof(cell_size));
  // Allocated cells have negative values, if the value is greater than zero its
  // unallocated
  if (cell_size > 0) {
    return;
  }
  expected = checkOffset(reg_contents.size(), offset + sizeof(cell_size));
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  offset += sizeof(cell_size);
  RegNameKey name_key;
  const int name_key_min_size = 76;
  // First 76 bytes contains known metadata, key name (dynamic size) begins
  // after 76 bytes
  memcpy(&name_key, &reg_contents[offset], name_key_min_size);
  const short nk = 27502; // name key
  if (name_key.sig != nk) {
    return;
  }

  expected = checkOffset(reg_contents.size(),
                         offset + name_key_min_size + name_key.key_name_size);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  std::string key_name(reg_contents.begin() + offset + name_key_min_size,
                       reg_contents.begin() + offset + name_key_min_size +
                           name_key.key_name_size);
  key_path.push_back(key_name);

  if (name_key.number_values == 0) {
    // Now have all the data to build the table (name key has no value keys)
    RegTableData reg_table;
    reg_table.key = osquery::join(key_path, "\\");
    reg_table.key_path = osquery::join(key_path, "\\");
    reg_table.key_type = "subkey";
    reg_table.modified_time = filetimeToUnixtime(name_key.timestamp);
    raw_reg.push_back(reg_table);
  } else {
    // Parse all value keys
    parseValueKeyList(reg_contents,
                      name_key.number_values,
                      name_key.value_list_offset,
                      raw_reg,
                      key_path,
                      name_key);
  }

  // Offset of negative one (0xffffffff) means an empty subkey
  if (name_key.sub_key_list_offset == -1) {
    depth_tracker--;
    key_path.pop_back();
    return;
  }

  // Parse the list of sub keys for name key. Will be either leaf hash, leaf
  // index, root index, or fast leaf
  parseCellList(reg_contents,
                name_key.sub_key_list_offset,
                raw_reg,
                key_path,
                offset_tracker,
                depth_tracker);
  key_path.pop_back();
  depth_tracker--;
}

// Get the data associated with Registry value key
std::string parseDataValue(const std::vector<char>& reg_contents,
                           const int& offset,
                           const int& size,
                           const std::string& reg_type) {
  std::string data;
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return data;
  }
  if (size == 0) {
    return data;
  }
  int data_size_and_slack = 0;
  // The raw registry data value can contain remnants of previous entries in
  // slack space, currently ignoring slack data for now
  memcpy(
      &data_size_and_slack, &reg_contents[offset], sizeof(data_size_and_slack));

  expected = checkOffset(reg_contents.size(),
                         offset + sizeof(data_size_and_slack) + size);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return data;
  }
  int total_offset = offset + sizeof(data_size_and_slack);

  // Format data base on Registry Type
  if (reg_type == "REG_SZ") {
    data = wideLiteralCharToString(reg_contents, total_offset, size);

  } else if (reg_type == "REG_BINARY" || reg_type == "REG_RESOURCE_LIST" ||
             reg_type == "REG_FULL_RESOURCE_DESCRIPTOR" ||
             reg_type == "REG_RESOURCE_REQUIREMENTS_LIST" ||
             reg_type == "REG_TYPE_UNKNOWN" || reg_type == "REG_NONE") {
    auto data_buff = std::make_unique<BYTE[]>(size);
    memcpy(data_buff.get(),
           &reg_contents[offset + sizeof(data_size_and_slack)],
           size);
    std::vector<char> reg_binary;
    for (size_t j = 0; j < size; j++) {
      reg_binary.push_back((char)data_buff[j]);
    }

    boost::algorithm::hex(
        reg_binary.begin(), reg_binary.end(), std::back_inserter(data));
    SecureZeroMemory(data_buff.get(), size);
  } else if (reg_type == "REG_DWORD") {
    int reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(reg_dword);
  } else if (reg_type == "REG_DWORD_BIG_ENDIAN") {
    int reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(_byteswap_ulong(reg_dword));
  } else if (reg_type == "REG_LINK") {
    data = wideLiteralCharToString(reg_contents, total_offset, size);
  } else if (reg_type == "REG_EXPAND_SZ") {
    data = wideLiteralCharToString(reg_contents, total_offset, size);
  } else if (reg_type == "REG_QWORD") {
    unsigned long long reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(reg_dword);
  } else if (reg_type == "REG_MULTI_SZ") {
    auto data_contents =
        (PWCHAR)(&reg_contents[0] + offset + sizeof(data_size_and_slack));
    size_t total_length{0};
    // Contains an array of wide strings
    std::vector<std::string> multi_string;
    while (*data_contents != L'\0') {
      auto length =
          wcsnlen_s(data_contents, (size - total_length) / sizeof(WCHAR));
      if (length == 0 || length == (size - total_length) / sizeof(WCHAR)) {
        // A null wide character was not found.
        break;
      }

      total_length += (length + 1) * sizeof(WCHAR);
      std::string multi_data = wstringToString(data_contents);
      if (multi_data != "") {
        multi_string.push_back(multi_data);
      }
      if (total_length >= size) {
        break;
      }
      data_contents += length + 1;
    }
    data = osquery::join(multi_string, ",");

  } else if (reg_type == "REG_FILETIME") {
    FILETIME file_time;
    memcpy(&file_time,
           &reg_contents[offset + sizeof(data_size_and_slack)],
           sizeof(file_time));
    data = std::to_string(filetimeToUnixtime(file_time));
  }
  return data;
}

// Get the Registry value keys
void parseValueKey(const std::vector<char>& reg_contents,
                   const int& reg_offset,
                   std::vector<RegTableData>& raw_reg,
                   std::vector<std::string>& key_path,
                   const RegNameKey& name_key) {
  // Offset of negative one (0xffffffff) means an empty subkey
  if (reg_offset == -1) {
    return;
  }
  // Always add 4096/0x1000 (header size) to any registry offset
  int hive_bin_offset = reg_offset + kheader_size;

  auto expected = checkOffset(reg_contents.size(), hive_bin_offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  int cell_size = 0;
  memcpy(&cell_size, &reg_contents[hive_bin_offset], sizeof(cell_size));

  // Allocated cells have negative values, if the value is greater than zero its
  // unallocated
  if (cell_size > 0) {
    return;
  }
  expected =
      checkOffset(reg_contents.size(), hive_bin_offset + sizeof(cell_size));
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  hive_bin_offset += sizeof(cell_size);
  RegValueKey value_key;
  const int value_min_size = 20;
  const short vk = 27510; // value key
  memcpy(&value_key, &reg_contents[hive_bin_offset], value_min_size);
  if (value_key.sig != vk) {
    return;
  }
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

  std::string reg_type;
  // Identify registry type
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
    expected = checkOffset(
        reg_contents.size(),
        value_min_size + hive_bin_offset + value_key.value_name_size);

    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    // Name is in ASCII otherwise its UTF16
    if (value_key.flags == 1) {
      std::string reg_value_name(
          reg_contents.begin() + value_min_size + hive_bin_offset,
          reg_contents.begin() + value_min_size + hive_bin_offset +
              value_key.value_name_size);
      name = reg_value_name;
    } else {
      int total_offset = hive_bin_offset + value_min_size;
      name = wideLiteralCharToString(
          reg_contents, total_offset, value_key.value_name_size);
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
  } else if (value_key.data_size > 16344) {
    // If data size is greater than 16344 it could be stored in Big Data cell
    // (Registry version higher than 1.3)
    if (value_key.data_offset != 0 && value_key.data_offset != -1) {
      int db_offset = value_key.data_offset + kheader_size;

      parseHiveBigData(
          reg_contents, db_offset, reg_type, value_key.data_size, data);
    }
  } else {
    int data_offset = value_key.data_offset + kheader_size;
    data = parseDataValue(
        reg_contents, data_offset, value_key.data_size, reg_type);
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

// Registry data values that contain more than 16344 bytes have Big
// data cells (DB). This cell only exists on Registry versions higher than 1.3
void parseHiveBigData(const std::vector<char>& reg_contents,
                      const int& offset,
                      const std::string& reg_type,
                      const int& data_size,
                      std::string& data_string) {
  const int size = 4;

  auto expected = checkOffset(reg_contents.size(), offset + size);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  RegBigData big_data;
  const int big_data_min_size = 8;

  memcpy(&big_data, &reg_contents[offset + size], big_data_min_size);

  const short db = 25188;
  // Check for "db". Seen when registry version
  // is higher than 1.3. Treat as normal registry data otherwise
  if (big_data.sig != db) {
    data_string = parseDataValue(reg_contents, offset, data_size, reg_type);
    return;
  }

  if (big_data.num_segments <= 0) {
    LOG(INFO) << "Did not identify any big data segments expected more than "
                 "zero, got: "
              << big_data.num_segments;
    return;
  }

  int segments = 0;
  // Big data segments contain offset to value key offset
  int db_list_offset = big_data.block_offset + kheader_size;
  std::vector<char> data_contents;
  // Add padding at beginning of contents to adjust for slack
  data_contents.push_back('0');
  data_contents.push_back('0');
  data_contents.push_back('0');
  data_contents.push_back('0');

  int segment_start = 0;
  // Loop through all segments and concat data. Compare offsets.
  while (segments < big_data.num_segments) {
    expected = checkOffset(reg_contents.size(), offset + size + segment_start);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    // Get offset to db data
    int db_data_offset = 0;
    memcpy(&db_data_offset,
           &reg_contents[db_list_offset + size + segment_start],
           sizeof(int));

    expected = checkOffset(reg_contents.size(), db_data_offset + kheader_size);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    // Get db data size
    int db_data_size = 0;
    memcpy(&db_data_size,
           &reg_contents[db_data_offset + kheader_size],
           sizeof(int));
    // Size is negative value
    if (db_data_size < 0) {
      db_data_size = db_data_size * -1;
    }

    expected = checkOffset(
        reg_contents.size(),
        db_data_offset + sizeof(int) + kheader_size + db_data_size - 8);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }

    // Concat and build data
    data_contents.insert(
        data_contents.end(),
        reg_contents.begin() + db_data_offset + sizeof(int) + kheader_size,
        reg_contents.begin() + db_data_offset + sizeof(int) + kheader_size +
            db_data_size - 8);
    segments++;
    segment_start += 4;
  }

  // Transform data into string
  data_string = parseDataValue(data_contents, 0, data_size, reg_type);
}

// Complex Registry key that contains Access Control Entries (ACE), permissions
// for registry keys. Currently not utilized due to complexity and limited value
void parseHiveSecurityKey(const std::vector<char>& reg_contents,
                          const int& reg_offset,
                          std::vector<RegTableData>& raw_reg,
                          std::vector<std::string>& key_path) {
  // Always add 4096/0x1000 (header size) to any registry offset
  int offset = reg_offset + kheader_size;

  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  int cell_size = 0;
  memcpy(&cell_size, &reg_contents[offset], sizeof(cell_size));
  // Allocated cells have negative values, if the value is greater than zero its
  // unallocated
  if (cell_size > 0) {
    return;
  }
  expected = checkOffset(reg_contents.size(), offset + sizeof(cell_size));
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  offset += sizeof(cell_size);
  const int security_key_min_size = 20;
  const short sk = 27507; // security key

  RegSecurityKey security_key;
  memcpy(&security_key, &reg_contents[offset], security_key_min_size);
  if (security_key.sig != sk) {
    return;
  }
  // Security descriptor contains all the ACE metadata
  std::vector<char> security_descriptor(
      reg_contents.begin() + offset + security_key_min_size,
      reg_contents.begin() + offset + security_key_min_size +
          security_key.security_descriptor_size);
}

// Function to handle all the Registry cell lists
void parseCellList(const std::vector<char>& reg_contents,
                   const int& hive_offset,
                   std::vector<RegTableData>& raw_reg,
                   std::vector<std::string>& key_path,
                   std::vector<int>& offset_tracker,
                   int& depth_tracker) {
  // Offset of negative one (0xffffffff) means an empty subkey
  if (hive_offset == -1) {
    return;
  }

  // Always add 4096/0x1000 (header size) to any registry offset
  int offset = hive_offset + kheader_size;

  // Compare offset to registry contents
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  // Registry key cell list types
  const short lh = 26732; // leaf hash
  const short li = 26988; // leaf index
  const short ri = 26994; // root index
  const short lf = 26220; // fast leaf

  int cell_size = 0;
  memcpy(&cell_size, &reg_contents[offset], sizeof(cell_size));
  // Allocated cells have negative values, if the value is greater than zero its
  // unallocated
  if (cell_size > 0) {
    return;
  }

  expected = checkOffset(reg_contents.size(), offset + sizeof(cell_size));
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  unsigned short cell_type = 0;
  memcpy(
      &cell_type, &reg_contents[offset + sizeof(cell_size)], sizeof(cell_type));

  if (cell_type == lf) {
    offset += sizeof(cell_size);
    parseHiveLeafHash(
        reg_contents, offset, raw_reg, key_path, offset_tracker, depth_tracker);
  } else if (cell_type == li) {
    offset += sizeof(cell_size);
    parseHiveLeafIndex(
        reg_contents, offset, raw_reg, key_path, offset_tracker, depth_tracker);
  } else if (cell_type == lh) {
    offset += sizeof(cell_size);
    parseHiveLeafHash(
        reg_contents, offset, raw_reg, key_path, offset_tracker, depth_tracker);
  } else if (cell_type == ri) {
    offset += sizeof(cell_size);
    parseHiveRootIndex(
        reg_contents, offset, raw_reg, key_path, offset_tracker, depth_tracker);
  }
}

std::vector<RegTableData> buildRegistry(std::vector<char>& reg_contents) {
  std::vector<RegTableData> raw_reg;
  RegHeader header;
  std::vector<int> offset_tracker;
  memcpy(&header, &reg_contents[0], kheader_size);
  const int reg_sig = 0x66676572;
  if (header.sig != reg_sig) {
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
  int depth_tracker = 0;
  // From the first Registry Name key we can parse and build the whole registry
  // tree
  parseNameKey(
      reg_contents, offset, raw_reg, key_path, offset_tracker, depth_tracker);
  return raw_reg;
}

std::vector<RegTableData> rawRegistry(const std::string& reg_path,
                                      const std::string& drive_path) {
  std::cout << reg_path << std::endl;
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
  std::cout << reg_contents.size() << std::endl;
  raw_reg = buildRegistry(reg_contents);
  return raw_reg;
}
} // namespace osquery
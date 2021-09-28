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
  try {
    offset_tracker.at(offset);
  } catch (std::out_of_range) {
    offset_tracker.push_back(offset);
    return ExpectedOffsetTracker::success(offset_tracker);
  }
  LOG(INFO) << "Duplicate offset: " << offset;
  return ExpectedOffsetTracker::failure(ConversionError::InvalidArgument,
                                        "Duplicate registry offset");
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

std::vector<char> rawReadRegistry(const std::string& reg_path,
                                  const std::string& drive_path) {
  SleuthkitHelper dh(drive_path);
  std::vector<char> reg_contents;
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
                        const int& offset,
                        std::vector<int>& offset_tracker) {
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

void parseHiveLeafHash(const std::vector<char>& reg_contents,
                       int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key,
                       std::vector<int>& offset_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }

  RegLeafHash leaf_hash;
  int leaf_hash_min_size = 4;
  memcpy(&leaf_hash, &reg_contents[offset], leaf_hash_min_size);
  int elements = 0;
  int element_offset = 0;
  int named_key_offset = 0;

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
    parseHiveCell(reg_contents,
                  named_key_offset,
                  raw_reg,
                  key_path,
                  name_key,
                  offset_tracker);
  }
}

void parseHiveLeafIndex(const std::vector<char>& reg_contents,
                        int& offset,
                        std::vector<RegTableData>& raw_reg,
                        std::vector<std::string>& key_path,
                        const RegNameKey& name_key,
                        std::vector<int>& offset_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  RegLeafHash leaf_index;
  int leaf_index_min_size = 4;
  memcpy(&leaf_index, &reg_contents[offset], leaf_index_min_size);
  int elements = 0;
  int element_offset = 0;
  int named_key_offset = 0;
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
    parseHiveCell(reg_contents,
                  named_key_offset,
                  raw_reg,
                  key_path,
                  name_key,
                  offset_tracker);
  }
}

void parseValueKeyList(const std::vector<char>& reg_contents,
                       const int& num_values,
                       const int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key,
                       std::vector<int>& offset_tracker) {
  int value_entries = 0;
  int unknown = 4;
  int value_list_offset = 0;
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
    parseHiveCell(reg_contents,
                  value_offset,
                  raw_reg,
                  key_path,
                  name_key,
                  offset_tracker);
    value_entries++;
  }
}

void parseNameKey(const std::vector<char>& reg_contents,
                  int& offset,
                  std::vector<RegTableData>& raw_reg,
                  std::vector<std::string>& key_path,
                  std::vector<int>& offset_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  RegNameKey name_key;
  const int name_key_min_size = 76;
  memcpy(&name_key, &reg_contents[offset], name_key_min_size);
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

  // Check if Security Key exists
  if (name_key.security_key_offset != -1) {
    // parseHiveCell(reg_contents,
    //               name_key.security_key_offset,
    //               raw_reg,
    //               key_path,
    //               name_key,
    //               offset_tracker);
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
                      name_key,
                      offset_tracker);
  }

  parseHiveCell(reg_contents,
                name_key.sub_key_list_offset,
                raw_reg,
                key_path,
                name_key,
                offset_tracker);
  key_path.pop_back();
}

// Get the data associated with Registry value key
std::string parseDataValue(const std::vector<char>& reg_contents,
                           const int& offset,
                           const int& size,
                           const std::string& reg_type,
                           std::vector<int>& offset_tracker) {
  std::string data;
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return data;
  }
  int data_size = size + 1;
  int data_size_and_slack = 0;
  // The raw registry data value can contain remnants of previous entries in
  // slack space, currently ignoring slack data for now
  memcpy(
      &data_size_and_slack, &reg_contents[offset], sizeof(data_size_and_slack));
  if (data_size == 0) {
    return data;
  }
  expected = checkOffset(reg_contents.size(),
                         offset + sizeof(data_size_and_slack) + data_size);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return data;
  }
  auto data_buff = std::make_unique<BYTE[]>(data_size);
  // Format data base on Registry Type (similar to the existing api registry
  // table)
  // std::cout << reg_type << std::endl;
  if (reg_type == "REG_SZ") {
    memcpy(data_buff.get(),
           &reg_contents[offset + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    data = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
  } else if (reg_type == "REG_BINARY0" || reg_type == "REG_RESOURCE_LIST" ||
             reg_type == "REG_FULL_RESOURCE_DESCRIPTOR" ||
             reg_type == "REG_RESOURCE_REQUIREMENTS_LIST" ||
             reg_type == "REG_TYPE_UNKNOWN" || reg_type == "REG_NONE") {
    memcpy(data_buff.get(),
           &reg_contents[offset + sizeof(data_size_and_slack)],
           data_size);
    std::vector<char> reg_binary;
    data_size--;
    for (size_t j = 0; j < data_size; j++) {
      reg_binary.push_back((char)data_buff[j]);
    }

    boost::algorithm::hex(
        reg_binary.begin(), reg_binary.end(), std::back_inserter(data));
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
    memcpy(data_buff.get(),
           &reg_contents[offset + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    data = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
  } else if (reg_type == "REG_EXPAND_SZ0") {
    memcpy(data_buff.get(),
           &reg_contents[offset + sizeof(data_size_and_slack)],
           data_size);
    data_buff[data_size - 1] = 0x00;

    data = wstringToString(reinterpret_cast<wchar_t*>(data_buff.get()));
  } else if (reg_type == "REG_QWORD") {
    unsigned long long reg_dword = 0;
    memcpy(&reg_dword,
           &reg_contents[offset + sizeof(data_size_and_slack)],
           sizeof(reg_dword));
    data = std::to_string(reg_dword);
  } else if (reg_type == "REG_MULTI_SZ") {
    memcpy(data_buff.get(),
           &reg_contents[offset + sizeof(data_size_and_slack)],
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
           &reg_contents[offset + sizeof(data_size_and_slack)],
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
                   const RegNameKey& name_key,
                   std::vector<int>& offset_tracker) {
  auto expected = checkOffset(reg_contents.size(), hive_bin_offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
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
  } else if (value_key.data_size > 16344) {
    int db_offset = value_key.data_offset + kheader_size;
    parseHiveBigData(reg_contents,
                     db_offset,
                     reg_type,
                     value_key.data_size,
                     data,
                     offset_tracker);
  } else {
    int data_offset = value_key.data_offset + kheader_size;
    data = parseDataValue(reg_contents,
                          data_offset,
                          value_key.data_size,
                          reg_type,
                          offset_tracker);
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
// data cells (DB)
void parseHiveBigData(const std::vector<char>& reg_contents,
                      const int& offset,
                      const std::string& reg_type,
                      const int& data_size,
                      std::string& data_string,
                      std::vector<int>& offset_tracker) {
  const int skip_unknown = 4;
  RegBigData big_data;
  const int big_data_min_size = 8;
  auto expected = checkOffset(reg_contents.size(), offset + skip_unknown);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  memcpy(&big_data, &reg_contents[offset + skip_unknown], big_data_min_size);
  int segments = 0;
  int segment_offset = 0;
  // Big data segments contain offset to value key offset
  int db_list_offset = big_data.block_offset + kheader_size;
  std::vector<char> data_contents;
  // Add padding at beginning of contents to adjust for slack
  data_contents.push_back('0');
  data_contents.push_back('0');
  data_contents.push_back('0');
  data_contents.push_back('0');

  int segment_start = 0;
  // Loop through all segments and concat data
  while (segments < big_data.num_segments) {
    expected =
        checkOffset(reg_contents.size(), offset + skip_unknown + segment_start);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }
    int db_data_offset = 0;
    memcpy(&db_data_offset,
           &reg_contents[db_list_offset + skip_unknown + segment_start],
           sizeof(int));
    expected = checkOffset(reg_contents.size(), db_data_offset + kheader_size);
    if (expected.isError()) {
      LOG(INFO) << expected.getError();
      return;
    }
    int db_data_size = 0;
    memcpy(&db_data_size,
           &reg_contents[db_data_offset + kheader_size],
           sizeof(int));
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
    data_contents.insert(
        data_contents.end(),
        reg_contents.begin() + db_data_offset + sizeof(int) + kheader_size,
        reg_contents.begin() + db_data_offset + sizeof(int) + kheader_size +
            db_data_size - 8);
    segments++;
    segment_start += 4;
  }
  data_string =
      parseDataValue(data_contents, 0, data_size, reg_type, offset_tracker);
}

// Complex Registry key that contains Access Control Entries (ACE), permissions
// for registry keys
void parseHiveSecurityKey(const std::vector<char>& reg_contents,
                          const int& offset,
                          std::vector<RegTableData>& raw_reg,
                          std::vector<std::string>& key_path,
                          const RegNameKey& name_key,
                          std::vector<int>& offset_tracker) {
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
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
                   const RegNameKey& name_key,
                   std::vector<int>& offset_tracker) {
  // Offset of negative one (0xffffffff) means an empty subkey
  if (hive_offset == -1) {
    return;
  }

  // Always add 4096/0x1000 (header size) to any registry offset
  int offset = hive_offset + kheader_size;
  auto expected = checkOffset(reg_contents.size(), offset);
  if (expected.isError()) {
    LOG(INFO) << expected.getError();
    return;
  }
  // auto expected_tracker =
  //    checkOffsetTracker(reg_contents.size(), offset, offset_tracker);
  // if (expected_tracker.isError()) {
  //  LOG(INFO) << expected.getError();
  //  return;
  //}
  // offset_tracker = expected_tracker.take();

  // Registry key types
  const short vk = 27510; // value key
  const short nk = 27502; // name key
  const short sk = 27507; // security key
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

  if (cell_type == nk) {
    offset += sizeof(cell_size);
    parseNameKey(reg_contents, offset, raw_reg, key_path, offset_tracker);
  } else if (cell_type == vk) {
    offset += sizeof(cell_size);
    parseValueKey(
        reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
  } else if (cell_type == sk) {
    offset += sizeof(cell_size);
    // parseHiveSecurityKey(
    //    reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
  } else if (cell_type == lf) {
    offset += sizeof(cell_size);
    parseHiveLeafHash(
        reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
  } else if (cell_type == li) {
    offset += sizeof(cell_size);
    parseHiveLeafIndex(
        reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
  } else if (cell_type == lh) {
    offset += sizeof(cell_size);
    parseHiveLeafHash(
        reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
  } else if (cell_type == ri) {
    offset += sizeof(cell_size);
    parseHiveLeafIndex(
        reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
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

  RegNameKey name_key;
  // From the first Registry Hive cell we can parse and build the whole registry
  // tree
  parseHiveCell(
      reg_contents, offset, raw_reg, key_path, name_key, offset_tracker);
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
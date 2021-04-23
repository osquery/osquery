/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/lzxpress.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <boost/algorithm/algorithm.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

namespace osquery {
namespace tables {
const std::string kPrefetchLocation = "C:\\Windows\\Prefetch\\";
// const std::string kPrefetchLocation = "C:\\Users\\bob\\Downloads\\";
struct PrefetchHeader {
  int file_size;
  std::string filename;
  std::string prefetch_hash;
};

std::vector<std::string> parseAccessedData(const std::string& data,
                                           const std::string& type) {
  std::vector<std::string> accessed_files;
  std::string list_data = data;
  size_t directory_beginning = 0;
  while (list_data.size() != 0) {
    if (type == "directory") {
      directory_beginning = list_data.find("5C0056004F004C0055004D004500");
      if (directory_beginning == std::string::npos) {
        directory_beginning = list_data.find("5C00440045005600490043004500");
      }
      list_data.erase(0, directory_beginning);
    }
    size_t name_size = list_data.find("000000");
    if (name_size == std::string::npos) {
      break;
    }
    std::string name = list_data.substr(0, name_size);
    boost::erase_all(name, "00");
    if (name_size % 2 != 0) {
      name += "0";
      name_size += 1;
    }
    try {
      std::string filename = boost::algorithm::unhex(name);
      accessed_files.push_back(filename);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode accessed " << type
                   << " hex values to string: " << data;
    }
    // Directories seem to have extra padding/bytes at the beginning
    if (type == "directory") {
      name_size = name_size + 4;
    }
    list_data.erase(0, name_size + 6);
    size_t has_data = list_data.find("5C0056004F004C0055004D004500");
    size_t has_data_win7 = list_data.find("5C00440045005600490043004500");

    // Directory lists can have random trailing data at the end
    // Win10 accessed data has \VOLUME at the beginning
    // Win7 and Win8 accessed data has \DEVICE at the beginning
    // If \VOLUME and \DEVICE are not found break
    if (has_data == std::string::npos && has_data_win7 == std::string::npos) {
      break;
    }
  }
  return accessed_files;
}

PrefetchHeader parseHeader(std::string& prefetch_data) {
  PrefetchHeader header_data;
  std::string size = prefetch_data.substr(24, 8);
  size = swapEndianess(size);
  header_data.file_size = tryTo<int>(size, 16).takeOr(-1);

  // Find UTF end-of-string character
  size_t name_end = prefetch_data.find("0000", 32);
  std::string name = prefetch_data.substr(32, name_end - 32);
  // std::cout << "Hex nameis: " << name << std::endl;

  // File names are in Unicode/UTF
  boost::erase_all(name, "00");
  if (name.size() % 2 != 0) {
    name += "0";
  }
  try {
    header_data.filename = boost::algorithm::unhex(name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode filename hex values to string: "
                 << prefetch_data;
  }
  std::string crc_hash = prefetch_data.substr(152, 8);
  header_data.prefetch_hash = swapEndianess(crc_hash);
  return header_data;
}

void parsePrefetchData(QueryData& results,
                       std::string& prefetch_data,
                       std::string& file_path,
                       int& version) {
  auto header = parseHeader(prefetch_data);

  std::string filename_list_offset = prefetch_data.substr(200, 8);
  filename_list_offset = swapEndianess(filename_list_offset);
  int offset = tryTo<int>(filename_list_offset, 16).takeOr(-1);
  if (offset == -1) {
    LOG(WARNING) << "Could not get file listing offset: " << prefetch_data;
    return;
  }
  std::string file_list_size = prefetch_data.substr(208, 8);
  file_list_size = swapEndianess(file_list_size);
  int size = tryTo<int>(file_list_size, 16).takeOr(-1);
  if (size == -1) {
    LOG(WARNING) << "Could not get file listing size: " << prefetch_data;
    return;
  }

  std::string file_list = prefetch_data.substr(offset * 2, size * 2);
  const std::string filename = "filename";
  std::vector<std::string> accessed_file_list =
      parseAccessedData(file_list, filename);

  std::string files_accessed_list = osquery::join(accessed_file_list, ",");

  std::string volume_list_offset = prefetch_data.substr(216, 8);
  volume_list_offset = swapEndianess(volume_list_offset);
  int volume_offset = tryTo<int>(volume_list_offset, 16).takeOr(-1);
  if (volume_offset == -1) {
    LOG(WARNING) << "Could not get volume listing offset: " << prefetch_data;
    return;
  }
  // std::cout << "Volume offset: " << volume_offset << std::endl;

  std::string str_volume_numbers = prefetch_data.substr(224, 8);
  str_volume_numbers = swapEndianess(str_volume_numbers);
  int volume_numbers = tryTo<int>(str_volume_numbers, 16).takeOr(-1);
  if (volume_numbers == -1) {
    LOG(WARNING) << "Could not get number of volumes: " << prefetch_data;
    return;
  }
  std::string volume_list_size = prefetch_data.substr(232, 8);

  volume_list_size = swapEndianess(volume_list_size);
  int volume_size = tryTo<int>(volume_list_size, 16).takeOr(-1);
  if (size == -1) {
    LOG(WARNING) << "Could not get volume listing size: " << prefetch_data;
    return;
  }

  std::string dir_list =
      prefetch_data.substr(volume_offset * 2, volume_size * 2);

  std::string volume_creation = dir_list.substr(16, 16);
  long long creation = 0LL;
  if (volume_creation != "0000000000000000") {
    creation = littleEndianToUnixTime(volume_creation);
  }
  std::string volume_serial = dir_list.substr(32, 8);
  volume_serial = swapEndianess(volume_serial);
  const std::string directory = "directory";
  std::vector<std::string> accessed_dirs_list =
      parseAccessedData(dir_list.substr(804), directory);
  std::string dirs_accessed_list = osquery::join(accessed_dirs_list, ",");

  std::string run_times = "0000000000000000";
  // Win8+ Prefetch can contain up to eight timestamps
  // If the eight timestamps are not filled, they are set to 0
  if (version == 23) {
    run_times = prefetch_data.substr(256, 16);
  } else {
    run_times = prefetch_data.substr(256, 128);
  }
  std::vector<std::string> timestamps;
  while (run_times.size() != 0) {
    if (run_times.substr(0, 16) == "0000000000000000") {
      break;
    }
    std::string time =
        std::to_string(littleEndianToUnixTime(run_times.substr(0, 16)));
    timestamps.push_back(time);
    run_times.erase(0, 16);
  }
  std::string timestamp_list = osquery::join(timestamps, ",");
  std::string run_count = "";
  if (version == 23) {
    run_count = prefetch_data.substr(304, 8);
  } else if (version == 26) {
    run_count = prefetch_data.substr(416, 8);
  } else {
    run_count = prefetch_data.substr(400, 8);
  }
  run_count = swapEndianess(run_count);

  int count = tryTo<int>(run_count, 16).takeOr(-1);
  if (count == -1) {
    LOG(WARNING) << "Could not convert run count to integer: " << prefetch_data;
    return;
  }
  Row r;
  r["path"] = file_path;
  r["filename"] = header.filename;
  r["hash"] = header.prefetch_hash;
  r["last_execution_time"] = INTEGER(timestamps[0]);
  r["other_execution_times"] = timestamp_list;
  r["count"] = INTEGER(count);
  r["size"] = INTEGER(header.file_size);
  r["volume_serial"] = volume_serial;
  r["volume_creation"] = INTEGER(creation);
  r["accessed_files"] = files_accessed_list;
  r["accessed_directories"] = dirs_accessed_list;
  results.push_back(r);
}

void parsePrefetchVersion(QueryData& results,
                          std::string& prefetch_data,
                          std::string& file_path) {
  std::cout << "lets parse the data!" << std::endl;
  std::string str_version = prefetch_data.substr(0, 8);
  str_version = swapEndianess(str_version);
  int version = tryTo<int>(str_version, 16).takeOr(0);
  // Currently supports Win7 and higher
  if (version == 30 || version == 23 || version == 26) {
    parsePrefetchData(results, prefetch_data, file_path, version);
  } else {
    LOG(WARNING) << "Unsupported prefetch file: " << file_path;
  }
}

QueryData genPrefetch(QueryContext& context) {
  QueryData results;
  std::vector<std::string> prefetch_files;
  if (listFilesInDirectory(kPrefetchLocation, prefetch_files)) {
    for (const auto& file : prefetch_files) {
      std::string prefetch_content;
      if (boost::algorithm::iends_with(file, ".pf") &&
          boost::filesystem::is_regular_file(file)) {
        std::cout << file << std::endl;
        std::ifstream input_file(file, std::ios::in | std::ios::binary);
        std::vector<char> compressed_data(
            (std::istreambuf_iterator<char>(input_file)),
            (std::istreambuf_iterator<char>()));
        input_file.close();
        int sig_size = 0;
        std::string header_sig = "";
        std::stringstream decom_ss;
        // Get header information
        for (const auto& data : compressed_data) {
          if (sig_size == 8) {
            break;
          }
          if (sig_size < 3) {
            header_sig += data;
          } else if (sig_size > 3) {
            std::stringstream value;
            value << std::setfill('0') << std::setw(2);
            value << std::hex << std::uppercase << (int)(unsigned char)(data);
            decom_ss << value.str();
          }
          sig_size++;
        }
        std::string data = "";
        std::string file_path = file;
        // Check for compression signature. Prefetch is compressed on Win8+
        if (header_sig == "MAM") {
          std::string prefetch_size = swapEndianess(decom_ss.str());
          unsigned long size =
              tryTo<unsigned long>(prefetch_size, 16).takeOr(0ul);
          if (size == 0l) {
            LOG(WARNING) << "Could not get prefetch data size for: "
                         << file_path;
            continue;
            // return results;
          }
          data = decompressLZxpress(compressed_data, size);
          if (data == "Error") {
            continue;
          }
        } else {
          std::stringstream prefetch_ss;

          for (const auto& data : compressed_data) {
            std::stringstream value;
            value << std::setfill('0') << std::setw(2);
            value << std::hex << std::uppercase << (int)(unsigned char)(data);
            prefetch_ss << value.str();
          }
          data = prefetch_ss.str();
        }
        parsePrefetchVersion(results, data, file_path);
      }
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
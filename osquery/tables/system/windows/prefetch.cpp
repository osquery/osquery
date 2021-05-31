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
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/lzxpress.h>

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#define PREFETCH_SIGNATURE_COMPRESSED '\x04MAM' // MAM\0x4
#define PREFETCH_SIGNATURE 'ACCS' // SCCA

namespace osquery {
namespace tables {
namespace {

const std::string kPrefetchLocation = (getSystemRoot() / "Prefetch\\").string();

struct PrefetchHeader {
  std::uint32_t file_size;
  std::string filename;
  std::string prefetch_hash;
};

struct PrefetchFileInfo {
  std::string files;
  size_t count;
};

#pragma pack(push, 1)
typedef struct _PREFETCH_COMPRESSED_HEADER {
  DWORD Signature;
  DWORD TotalUncompressedSize;
  BYTE CompressedData[1]; // arbitrary size
} PREFETCH_COMPRESSED_HEADER, *PPREFETCH_COMPRESSED_HEADER;

typedef struct _PREFETCH_FILE_HEADER {
  DWORD Version;
  DWORD Signature;
  DWORD Reserved1;
  DWORD FileSize;
  WCHAR FileName[30];
  DWORD Hash;
  DWORD Reserved2;
} PREFETCH_FILE_HEADER, *PPREFETCH_FILE_HEADER;

typedef struct _PREFETCH_FILE_INFORMATION {
  DWORD FileMetricsArrayOffset;
  DWORD NumberOfMetricEntries;
  DWORD TraceChainsArrayOffset;
  DWORD NumberOfTraceChains;
  DWORD FileNameStringsOffset;
  DWORD FileNameStringsSize;
  DWORD VolumeInformationOffset;
  DWORD NumberOfVolumes;
  DWORD VolumesInformationSize;
  FILETIME LastRunTime;
  DWORD Reserved1[4];
  DWORD RunCount;
  DWORD Reserved2;
} PREFETCH_FILE_INFORMATION, *PPREFETCH_FILE_INFORMATION;

typedef struct _PREFETCH_VOLUME_INFORMATION {
  DWORD VolumePathOffset;
  DWORD VolumeDevicePathNumberOfCharacters;
  FILETIME VolumeCreationTime;
  DWORD VolumeSerialNumber;
  DWORD FileReferencesOffset;
  DWORD FileReferencesDataSize;
  DWORD DirectoryStringsOffset;
  DWORD NumberOfDirectoryStrings;
  DWORD Reserved1;
} PREFETCH_VOLUME_INFORMATION, *PPREFETCH_VOLUME_INFORMATION;

typedef struct _DIRECTORY_STRING {
  USHORT Size;
  WCHAR Directory[1]; // arbitrary size
} DIRECTORY_STRING, *PDIRECTORY_STRING;
#pragma pack(pop)

} // namespace

// Convert UTF16 UCHAR vectors to string
std::string ucharToString(std::string_view data) {
  size_t data_char = 0;
  std::string data_string;
  while (data_char < data.size() && data[data_char] != '\0') {
    data_string += data[data_char];
    data_char++;
    if (data_char == data.size()) {
      break;
    }
    if (data[data_char] == '\0') {
      data_char++;
    }
  }
  return data_string;
}

std::vector<std::string> parseAccessedData(std::string_view data_view,
                                           bool directory) {
  std::vector<std::string> accessed_data;

  while (data_view.size() > 0) {
    std::string file_accessed = ucharToString(data_view);
    if (file_accessed.size() == 0) {
      break;
    }

    size_t size = 2;
    if (directory) {
      if (file_accessed.size() < 4) {
        break;
      }

      size += 2;
      file_accessed = file_accessed.substr(1);
    }

    auto check_name = file_accessed.substr(0, 8);
    // Check if data does not begin with \VOLUME{ or \DEVICE{
    if (check_name != "\\VOLUME{" && check_name != "\\DEVICE{") {
      break;
    }

    accessed_data.push_back(file_accessed);
    data_view = data_view.substr((file_accessed.size() * 2) + size);
  }
  return accessed_data;
}

PrefetchHeader parseHeader(const PREFETCH_FILE_HEADER* data) {
  PrefetchHeader result;
  result.filename = wstringToString(data->FileName);
  result.prefetch_hash = (boost::format("%x") % data->Hash).str();
  result.file_size = data->FileSize;
  return result;
}

PrefetchFileInfo parseFileInfo(std::string_view data_view) {
  PrefetchFileInfo result;
  const auto file_info = (PPREFETCH_FILE_INFORMATION)(
      &data_view.data()[0] + sizeof(PREFETCH_FILE_HEADER));

  auto size = file_info->FileNameStringsSize;
  auto offset = file_info->FileNameStringsOffset;
  if (offset < 0 || offset > data_view.size()) {
    // Unexpected offset.
    return result;
  }

  if (size < 0 || size + offset > data_view.size()) {
    // Unexpected size.
    return result;
  }

  std::vector<std::string> filenames;
  auto next = (PWCHAR)(&data_view.data()[0] + offset);
  while (*next != '\0') {
    auto filename = wstringToString(next);
    if (filename.size() < 8) {
      break;
    }
    auto prefix = filename.substr(0, 8);
    if (prefix != "\\VOLUME{" && prefix != "\\DEVICE") {
      break;
    }
    filenames.emplace_back(std::move(filename));
    auto length = wcslen(next);
    next += length + 1;
  }
  result.files = osquery::join(filenames, ",");
  result.count = filenames.size();
  return result;
}

void parsePrefetchData(RowYield& yield,
                       const std::vector<UCHAR>& data,
                       const std::string& file_path) {
  const auto prefetch_header = (PPREFETCH_FILE_HEADER)&data[0];
  if (prefetch_header->Signature != PREFETCH_SIGNATURE) {
    LOG(INFO) << "Unsupported prefetch file header: " << file_path;
    return;
  }

  const auto version = prefetch_header->Version;
  if (version != 30 && version != 23 && version != 26) {
    LOG(INFO) << "Unsupported prefetch file version: " << file_path;
    return;
  }

  // check size is > 204?
  auto header = parseHeader(prefetch_header);

  const std::string_view data_view(reinterpret_cast<const char*>(data.data()),
                                   data.size());

  auto files_accessed = parseFileInfo(data_view);

  std::int32_t offset{0};
  std::int32_t size{0};
  memcpy(&offset, &data[108], sizeof(offset));
  std::int32_t volume_numbers = 0;
  memcpy(&volume_numbers, &data[112], sizeof(volume_numbers));
  memcpy(&size, &data[116], sizeof(size));

  if (offset < 0 || offset > data_view.size()) {
    // Unexpected offset.
    return;
  }

  if (size < 0 || offset + size > data_view.size()) {
    // Unexpected size.
    return;
  }

  auto dir_accessed_view = data_view.substr(offset, size);
  auto dir_view = dir_accessed_view;

  std::string volume_creation;
  std::string volume_serial;
  std::vector<std::int32_t> dir_lists;
  {
    std::vector<std::string> volume_creation_list;
    std::vector<std::string> volume_serial_list;
    while (volume_numbers > 0) {
      if (dir_view.size() < 32) {
        // Not enough data to parse.
        break;
      }

      std::int64_t creation = 0;
      memcpy(&creation, &dir_view.data()[8], sizeof(creation));
      LARGE_INTEGER large_time;
      large_time.QuadPart = creation;
      FILETIME file_time;
      file_time.dwHighDateTime = large_time.HighPart;
      file_time.dwLowDateTime = large_time.LowPart;
      LONGLONG creation_time = filetimeToUnixtime(file_time);
      volume_creation_list.push_back(std::to_string(creation_time));
      std::int32_t serial = 0;
      memcpy(&serial, &dir_view.data()[16], sizeof(serial));
      volume_serial_list.push_back((boost::format("%x") % serial).str());
      volume_numbers -= 1;
      std::int32_t list_offset = 0;
      memcpy(&list_offset, &dir_view.data()[28], sizeof(list_offset));
      dir_lists.push_back(list_offset);
      // Volume metadata size depends on Prefetch version
      if (version == 30) {
        dir_view.remove_prefix(96);
      } else {
        dir_view.remove_prefix(104);
      }
    }
    volume_creation = osquery::join(volume_creation_list, ",");
    volume_serial = osquery::join(volume_serial_list, ",");
  }

  std::string dirs_accessed;
  size_t dirs_accessed_count{0};
  {
    std::vector<std::string> dirs_accessed_list;
    for (const auto& dir_list : dir_lists) {
      auto dir_view = dir_accessed_view.substr(dir_list);
      auto dir = parseAccessedData(dir_view, true);
      dirs_accessed_list.insert(
          dirs_accessed_list.end(), dir.begin(), dir.end());
    }
    dirs_accessed = osquery::join(dirs_accessed_list, ",");
    dirs_accessed_count = dirs_accessed_list.size();
  }

  std::string timestamp_list;
  std::string last_execution_time;
  {
    std::vector<std::int64_t> run_times;
    std::int64_t times_run = 0;
    // Win8+ Prefetch can contain up to eight timestamps
    // If the eight timestamps are not filled, they are set to 0
    if (version == 23) {
      memcpy(&times_run, &data[128], sizeof(times_run));
      run_times.push_back(times_run);
    } else {
      int time_i = 0;
      int time_offset = 128;
      while (time_i < 8) {
        memcpy(&times_run, &data[time_offset], sizeof(times_run));
        run_times.push_back(times_run);
        time_i++;
        time_offset += 8;
      }
    }

    std::vector<std::string> timestamps;
    for (const auto& run_time : run_times) {
      if (run_time == 0ll) {
        break;
      }
      LARGE_INTEGER large_time;
      large_time.QuadPart = run_time;
      FILETIME file_time;
      file_time.dwHighDateTime = large_time.HighPart;
      file_time.dwLowDateTime = large_time.LowPart;
      LONGLONG runtime = filetimeToUnixtime(file_time);
      timestamps.push_back(std::to_string(runtime));
    }
    timestamp_list = osquery::join(timestamps, ",");
    if (!timestamps.empty()) {
      last_execution_time = timestamps[0];
    }
  }

  std::int32_t run_count = 0;
  if (version == 23) {
    memcpy(&run_count, &data[152], sizeof(run_count));
  } else if (version == 26) {
    memcpy(&run_count, &data[208], sizeof(run_count));
  } else {
    memcpy(&run_count, &data[200], sizeof(run_count));
  }

  auto r = make_table_row();
  r["path"] = file_path;
  r["filename"] = SQL_TEXT(header.filename);
  r["hash"] = header.prefetch_hash;
  r["size"] = INTEGER(header.file_size);
  r["accessed_files_count"] = INTEGER(files_accessed.count);
  r["accessed_files"] = std::move(files_accessed.files);
  r["volume_serial"] = std::move(volume_serial);
  r["volume_creation"] = std::move(volume_creation);
  r["accessed_directories_count"] = INTEGER(dirs_accessed_count);
  r["accessed_directories"] = std::move(dirs_accessed);
  r["last_execution_time"] = last_execution_time;
  r["execution_times"] = std::move(timestamp_list);
  r["count"] = INTEGER(run_count);
  yield(std::move(r));
}

void parsePrefetch(const std::string& file_path, RowYield& yield) {
  std::ifstream input_file(file_path, std::ios::in | std::ios::binary);
  std::vector<UCHAR> compressed_data(
      (std::istreambuf_iterator<char>(input_file)),
      (std::istreambuf_iterator<char>()));
  input_file.close();

  if (compressed_data.size() < sizeof(PPREFETCH_COMPRESSED_HEADER)) {
    // Not enough data to determine header size.
    return;
  }

  std::vector<UCHAR> data;
  const auto compressed_header =
      (PPREFETCH_COMPRESSED_HEADER)&compressed_data[0];
  if (compressed_header->Signature == PREFETCH_SIGNATURE_COMPRESSED) {
    auto expected = decompressLZxpress(
        compressed_data, compressed_header->TotalUncompressedSize);
    if (expected.isError()) {
      LOG(INFO) << "Could not decompress prefetch " << expected.getError();
      return;
    }
    data = expected.take();
  } else {
    data = std::move(compressed_data);
  }

  if (data.size() < sizeof(PPREFETCH_FILE_HEADER)) {
    // Not enough data to determine signature.
    return;
  }

  parsePrefetchData(yield, data, file_path);
}

void genPrefetch(RowYield& yield, QueryContext& context) {
  // There are no required columns for prefetch, but prefetch can take a bit of
  // time to parse. If a path constraint is provided parse only prefetch file(s)
  // in path
  auto paths = context.constraints["path"].getAll(EQUALS);
  // Expand constraints
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  auto prefetch_files = std::vector(paths.begin(), paths.end());
  if (prefetch_files.empty()) {
    listFilesInDirectory(kPrefetchLocation, prefetch_files);
  }

  for (const auto& file_path : prefetch_files) {
    if (!boost::algorithm::iends_with(file_path, ".pf")) {
      continue;
    }

    boost::system::error_code ec;
    if (boost::filesystem::is_regular_file(file_path, ec) && !ec) {
      parsePrefetch(file_path, yield);
    }
  }
}
} // namespace tables
} // namespace osquery

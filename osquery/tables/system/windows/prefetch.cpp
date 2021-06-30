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
const unsigned int kPrefetchVersionWindows10 = 30;
const unsigned int kPrefetchVersionWindows8 = 26;
const unsigned int kPrefetchVersionWindows7 = 23;
const unsigned int kPrefetchVolumeSizeWindows10 = 96;
const unsigned int kPrefetchVolumeSizeWindows8 = 104;

struct PrefetchHeader {
  std::uint32_t file_size;
  std::string filename;
  std::string prefetch_hash;
};

struct PrefetchFileInfo {
  std::string files;
  size_t files_count;
  LONGLONG last_run_time;
  std::string run_times;
  size_t run_count;
};

struct PrefetchVolumeInfo {
  std::string directories;
  size_t directories_count;
  std::string volume_serial;
  std::string volume_creation;
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
  union {
    struct {
      DWORD Reserved1[2];
      FILETIME LastRunTime;
      DWORD Reserved2[4];
      DWORD RunCount;
    } v23;
    struct {
      DWORD Reserved1[2];
      FILETIME LastRunTime;
      FILETIME OtherRunTimes[7];
      DWORD Reserved2[4];
      DWORD RunCount;
    } v26;
    struct {
      DWORD Reserved1[2];
      FILETIME LastRunTime;
      FILETIME OtherRunTimes[7];
      DWORD Reserved2[2];
      DWORD RunCount;
    } v30v2;
  } ext;
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

PrefetchHeader parseHeader(const PREFETCH_FILE_HEADER* header) {
  PrefetchHeader result;
  if (header->FileName[ARRAYSIZE(header->FileName) - 1] == L'\0') {
    result.filename = wstringToString(header->FileName);
  }
  if (result.filename.empty()) {
    LOG(INFO) << "Did not find null-terminated filename for prefetch file";
  }
  result.prefetch_hash = (boost::format("%x") % header->Hash).str();
  result.file_size = header->FileSize;
  return result;
}

PrefetchFileInfo parseFileInfo(
    const std::vector<UCHAR>& data,
    const PREFETCH_FILE_INFORMATION* prefetch_file_info,
    DWORD version) {
  PrefetchFileInfo result;

  FILETIME last_run_time;
  std::vector<std::string> run_times;

  switch (version) {
  case kPrefetchVersionWindows10:
    last_run_time = prefetch_file_info->ext.v30v2.LastRunTime;
    result.run_count = prefetch_file_info->ext.v30v2.RunCount;
    for (const auto& entry : prefetch_file_info->ext.v30v2.OtherRunTimes) {
      LONGLONG time = filetimeToUnixtime(entry);
      if (time != -11644473600) {
        run_times.push_back(std::to_string(filetimeToUnixtime(entry)));
      }
    }
    result.run_times = osquery::join(run_times, ",");

    break;
  case kPrefetchVersionWindows8:
    last_run_time = prefetch_file_info->ext.v26.LastRunTime;
    result.run_count = prefetch_file_info->ext.v26.RunCount;
    for (const auto& entry : prefetch_file_info->ext.v30v2.OtherRunTimes) {
      run_times.push_back(std::to_string(filetimeToUnixtime(entry)));
    }
    result.run_times = osquery::join(run_times, ",");
    break;
  case kPrefetchVersionWindows7:
    last_run_time = prefetch_file_info->ext.v23.LastRunTime;
    result.run_count = prefetch_file_info->ext.v23.RunCount;
    break;
  default:
    LOG(INFO) << "Unsupported prefetch version: " << version;
  }

  result.last_run_time = filetimeToUnixtime(last_run_time);

  // Size is given in bytes.
  const auto size = prefetch_file_info->FileNameStringsSize;
  const auto offset = prefetch_file_info->FileNameStringsOffset;
  if (offset > data.size()) {
    // Unexpected offset.
    return result;
  }

  size_t total_length{0};
  std::vector<std::string> filenames;
  auto next = (PWCHAR)(&data[0] + offset);
  while (*next != L'\0') {
    auto length = wcsnlen_s(next, (size - total_length) / sizeof(WCHAR));
    if (length == 0 || length == (size - total_length) / sizeof(WCHAR)) {
      // A null wide character was not found.
      break;
    }

    auto filename = wstringToString(next);
    filenames.emplace_back(std::move(filename));
    total_length += (length + 1) * sizeof(WCHAR);
    if (total_length >= size) {
      break;
    }
    next += length + 1;
  }

  result.files = osquery::join(filenames, ",");
  result.files_count = filenames.size();
  return result;
}

PrefetchVolumeInfo parseVolumeInfo(
    const std::vector<UCHAR>& data,
    const PREFETCH_FILE_INFORMATION* prefetch_file_info,
    DWORD version) {
  PrefetchVolumeInfo result;

  const auto volume_header_size = (version == kPrefetchVersionWindows10)
                                      ? kPrefetchVolumeSizeWindows10
                                      : kPrefetchVolumeSizeWindows8;
  const auto volume_offset = prefetch_file_info->VolumeInformationOffset;
  // Size is given in bytes.
  const auto volume_size = prefetch_file_info->VolumesInformationSize;
  if (volume_offset > data.size()) {
    // Unexpected offset.
    return result;
  }

  // Headers are stacked sequentially.
  auto volume_header_offset = volume_offset;

  std::vector<std::string> directories;
  std::vector<std::string> volume_serials;
  std::vector<std::string> volume_creations;
  for (size_t i = 0; i < prefetch_file_info->NumberOfVolumes; i++) {
    if (volume_header_offset + volume_header_size > data.size()) {
      // Unexpected size.
      return result;
    }

    const auto prefetch_volume_info =
        (PPREFETCH_VOLUME_INFORMATION)(&data[0] + volume_header_offset);
    const auto creation =
        filetimeToUnixtime(prefetch_volume_info->VolumeCreationTime);
    volume_creations.push_back(std::to_string(creation));
    const auto serial = prefetch_volume_info->VolumeSerialNumber;
    volume_serials.push_back((boost::format("%x") % serial).str());
    volume_header_offset += volume_header_size;

    const auto dir_count = prefetch_volume_info->NumberOfDirectoryStrings;
    size_t dir_offset = prefetch_volume_info->DirectoryStringsOffset;
    if (dir_count == 0) {
      continue;
    }

    for (size_t j = 0; j < dir_count; j++) {
      if (volume_offset + dir_offset + sizeof(PDIRECTORY_STRING) >
          data.size()) {
        // Unexpected offset.
        break;
      }

      const auto prefetch_directory =
          (PDIRECTORY_STRING)(&data[0] + volume_offset + dir_offset);
      dir_offset += sizeof(DIRECTORY_STRING);

      auto length = wcsnlen_s(prefetch_directory->Directory,
                              (volume_size - dir_offset) / sizeof(WCHAR));
      if (length == 0 || length == (volume_size - dir_offset) / sizeof(WCHAR)) {
        // A null wide character was not found.
        break;
      }

      auto filename = wstringToString(prefetch_directory->Directory);
      directories.emplace_back(std::move(filename));
      dir_offset += (length + 1) * sizeof(WCHAR);
    }
  }

  result.volume_creation = osquery::join(volume_creations, ",");
  result.volume_serial = osquery::join(volume_serials, ",");
  result.directories = osquery::join(directories, ",");
  result.directories_count = directories.size();
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
  if (version != kPrefetchVersionWindows10 &&
      version != kPrefetchVersionWindows7 &&
      version != kPrefetchVersionWindows8) {
    LOG(INFO) << "Unsupported prefetch file version: " << file_path;
    return;
  }

  auto header = parseHeader(prefetch_header);

  const auto prefetch_file_info =
      (PPREFETCH_FILE_INFORMATION)(&data[0] + sizeof(PREFETCH_FILE_HEADER));
  auto file_info = parseFileInfo(data, prefetch_file_info, version);
  auto volume_info = parseVolumeInfo(data, prefetch_file_info, version);

  auto r = make_table_row();
  r["path"] = file_path;
  r["filename"] = SQL_TEXT(header.filename);
  r["hash"] = header.prefetch_hash;
  r["size"] = INTEGER(header.file_size);
  r["accessed_files_count"] = INTEGER(file_info.files_count);
  r["accessed_files"] = std::move(file_info.files);
  r["volume_serial"] = std::move(volume_info.volume_serial);
  r["volume_creation"] = std::move(volume_info.volume_creation);
  r["accessed_directories_count"] = INTEGER(volume_info.directories_count);
  r["accessed_directories"] = std::move(volume_info.directories);
  r["last_run_time"] = INTEGER(file_info.last_run_time);

  if (version != kPrefetchVersionWindows7) {
    r["other_run_times"] = file_info.run_times;
  }

  r["run_count"] = INTEGER(file_info.run_count);
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
      LOG(INFO) << "Cannot decompress prefetch file: " << expected.getError();
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

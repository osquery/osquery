/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <string>
#include <windows.h>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/base64.h>
#include <osquery/utils/chars.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kZoneIdentifierKey = "Zone.Identifier";

void setRow(QueryData& results,
            const std::string& path,
            const std::string& key,
            const std::string& value) {
  Row r;
  r["path"] = path;
  r["directory"] = boost::filesystem::path(path).parent_path().string();
  r["key"] = key;
  auto value_printable = isPrintable(value);
  r["value"] = value_printable ? value : base64::encode(value);
  r["base64"] = value_printable ? INTEGER(0) : INTEGER(1);
  results.push_back(r);
}

void parseZoneIdentifier(QueryData& results,
                         const std::string& path,
                         const std::string& streamData) {
  auto lines = split(streamData, "\n");
  for (const auto& line : lines) {
    auto key_len = line.find_first_of("=");
    if (key_len == std::string::npos) {
      continue;
    }

    setRow(results,
           path,
           line.substr(0, key_len),
           line.substr(key_len + 1, line.size()));
  }
}

// Process a file and extract all stream names and data.
void enumerateStreams(QueryData& results, const std::string& path) {
  WIN32_FIND_STREAM_DATA findStreamData;
  HANDLE hFind = FindFirstStreamW(stringToWstring(path).c_str(),
                                  FindStreamInfoStandard,
                                  &findStreamData,
                                  0);

  auto fd_guard = scope_guard::create([&] { FindClose(hFind); });

  bool isFirstStream = true;

  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      // Skip first stream
      if (isFirstStream) {
        isFirstStream = false;
        continue;
      }
      std::string stream(wstringToString(findStreamData.cStreamName));

      // Split the stream string into a name and a type, format is
      // ":streamname:$streamtype"
      size_t splitPos = stream.find(':', 1);
      std::string streamName = stream.substr(1, splitPos - 1);

      std::stringstream streamPath;
      streamPath << path << ":" << streamName;
      std::string streamData;

      if (!readFile(streamPath.str(), streamData).ok()) {
        LOG(INFO) << "Couldn't read stream data: " << streamPath.str();
        return;
      }

      if (streamName == kZoneIdentifierKey) {
        parseZoneIdentifier(results, path, streamData);
      } else {
        // Remove trailing newlines
        boost::trim_right(streamData);
        setRow(results, path, streamName, streamData);
      }
    } while (FindNextStreamW(hFind, &findStreamData));
  } else {
    auto error_code = GetLastError();
    if (error_code != ERROR_HANDLE_EOF) {
      LOG(INFO) << "Error occurred while searching for streams in " << path
                << ". Error code: " << error_code;
    }
  }
}

QueryData genAds(QueryContext& context) {
  QueryData results;
  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
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

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    boost::system::error_code ec;
    // Folders can have ADS streams too
    if (!(boost::filesystem::is_regular_file(path, ec) ||
          boost::filesystem::is_directory(path, ec))) {
      continue;
    }
    enumerateStreams(results, path.string());
  }

  // Resolve directories for EQUALS and LIKE operations.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  context.expandConstraints(
      "directory",
      LIKE,
      directories,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FOLDERS | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Now loop through constraints using the directory column constraint.
  for (const auto& directory_string : directories) {
    if (!isReadable(directory_string) || !isDirectory(directory_string)) {
      continue;
    }

    std::vector<std::string> files;
    if (listFilesInDirectory(directory_string, files).ok()) {
      for (const auto& file : files) {
        enumerateStreams(results, file);
      }
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery

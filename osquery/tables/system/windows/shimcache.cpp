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
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/optional.hpp>

#include <algorithm>
#include <string>

const int kWin8 = 256;
const int kWin10PreCreator = 96;
const int kWin10Creator = 104;
const std::string kWin8Start = "80";
const std::string kWin10Start = "30";
const std::string kWin10CreatorStart = "34";
const std::string kWin8110ShimcacheDelimiter = "31307473";

// Shimcache can be in multiple ControlSets (ControlSet001, ControlSet002, etc)
const std::string kShimcacheControlset =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\%ControlSet%\\Control\\Session "
    "Manager\\AppCompatCache";

struct ShimcacheData {
  std::string path;
  long long last_modified;
  boost::optional<bool> execution_flag;
};

namespace osquery {
namespace tables {

auto parseShimcacheData(const std::string& token,
                        const boost::optional<bool>& execution_flag_exists) {
  ShimcacheData shimcache;
  std::string path_length = token.substr(16, 4);

  // swap endianess
  std::reverse(path_length.begin(), path_length.end());

  for (std::size_t i = 0; i < path_length.length(); i += 2) {
    std::swap(path_length[i], path_length[i + 1]);
  }

  // Convert string to size_t for file path length
  uint64_t shimcache_file_path =
      tryTo<std::uint64_t>(path_length, 16).takeOr(0_sz);

  // If the file path length is zero then there is no path
  if (shimcache_file_path == 0) {
    shimcache.last_modified = 0LL;
    return shimcache;
  }

  // Registry data is in Unicode (extra 0x00)
  std::string path = token.substr(20, (size_t)shimcache_file_path * 2);
  boost::erase_all(path, "00");

  // Windows Store entries have extra data, the extra data includes tabs in the
  // entry (Unicode value 09). Convert to spaces due to table formatting
  // issues
  boost::replace_all(path, "09", "20");
  std::string string_path;

  // Convert hex path to readable string
  try {
    string_path = boost::algorithm::unhex(path);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode Shimcache hex values to string: " << path;
    shimcache.last_modified = 0LL;
    return shimcache;
  }

  shimcache.path = string_path;
  size_t shimcache_modified_start = 0;
  size_t execution_flag_start = 0;

  // If execution flag exists set where the flag starts in the substring
  if (execution_flag_exists == true) {
    shimcache_modified_start = 40;
    execution_flag_start = 24;
  } else {
    shimcache_modified_start = 20;
  }
  std::string shimcache_time = token.substr(
      shimcache_modified_start + (size_t)shimcache_file_path * 2, 16);

  // Sometimes Shimcache artifacts have 0 as timestamp, if so skip filetime
  // conversion
  shimcache.last_modified = (shimcache_time == "0000000000000000")
                                ? 0LL
                                : littleEndianToUnixTime(shimcache_time);

  if (execution_flag_exists == true) {
    int shimcache_flag =
        tryTo<int>(
            token.substr(execution_flag_start + (size_t)shimcache_file_path * 2,
                         2),
            16)
            .takeOr(0);
    // Perform Bitwise AND to determine TRUE or FALSE
    if (shimcache_flag & 2) {
      shimcache.execution_flag = true;
    } else {
      shimcache.execution_flag = false;
    }
  }
  return shimcache;
}

void parseEntry(const Row& aKey, size_t& index, QueryData& results) {
  boost::optional<bool> execution_flag_exists;
  std::string delimter;
  std::string data = aKey.at("data");

  // Check if Registry data starts with any of supported WIN_START
  // values and if the Shimcache delimiter exists at the specific
  // substring
  if ((boost::starts_with(data, kWin8Start)) &&
      (data.substr(kWin8, 8) == kWin8110ShimcacheDelimiter)) {
    execution_flag_exists = true;
    delimter = kWin8110ShimcacheDelimiter;
  } else if (boost::starts_with(data, kWin10Start) &&
             (data.substr(kWin10PreCreator, 8) == kWin8110ShimcacheDelimiter)) {
    delimter = kWin8110ShimcacheDelimiter;
  } else if (boost::starts_with(data, kWin10CreatorStart) &&
             (data.substr(kWin10Creator, 8) == kWin8110ShimcacheDelimiter)) {
    delimter = kWin8110ShimcacheDelimiter;
  } else {
    LOG(WARNING) << "Unknown or unsupported shimcache data: "
                 << data.substr(256, 8);
    return;
  }

  bool first_run = true;
  size_t pos = 0;
  std::string token;

  auto createRow = [&results, &index](const ShimcacheData& shimcache) {
    Row r;
    r["entry"] = INTEGER(index);
    r["path"] = SQL_TEXT(shimcache.path);
    r["modified_time"] = INTEGER(shimcache.last_modified);
    if (shimcache.execution_flag.is_initialized()) {
      if (shimcache.execution_flag.get()) {
        r["execution_flag"] = INTEGER(1);
      } else {
        r["execution_flag"] = INTEGER(0);
      }
    } else {
      r["execution_flag"] = INTEGER(-1);
    }
    results.push_back(std::move(r));
  };

  // Find all entries base on shimcache data delimter
  while ((pos = data.find(delimter)) != std::string::npos) {
    token = data.substr(0, pos);

    // Skip all the data before the first delimter match
    if (token.length() > 20) {
      if (first_run) {
        first_run = false;
        data.erase(0, pos + delimter.length());
        continue;
      }
      createRow(parseShimcacheData(token, execution_flag_exists));
      index++;
    } else {
      LOG(ERROR) << "Shimcache entry does not meet length requirements: "
                 << token;
    }
    data.erase(0, pos + delimter.length());
  }

  // Get last appcopmat entry
  token = data.substr(0, pos);
  if (token.length() > 20) {
    createRow(parseShimcacheData(token, execution_flag_exists));
  } else {
    LOG(ERROR) << "Shimcache entry does not meet length requirements: "
               << token;
  }
}

QueryData genShimcache(QueryContext& context) {
  QueryData results;
  std::set<std::string> shimcacheResults;

  expandRegistryGlobs(kShimcacheControlset, shimcacheResults);
  for (const auto& rKey : shimcacheResults) {
    auto entry = rKey.find("Control\\Session Manager\\AppCompatCache");
    if (entry == std::string::npos) {
      continue;
    }

    QueryData entryResults;
    size_t index = 1;
    queryKey(rKey, entryResults);
    for (const auto& aKey : entryResults) {
      if (aKey.at("name") != "AppCompatCache") {
        continue;
      }
      parseEntry(aKey, index, results);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery

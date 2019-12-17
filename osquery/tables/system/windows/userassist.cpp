/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/tables/system/windows/userassist.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/system/time.h>
#include <string>

namespace osquery {
namespace tables {

constexpr auto kFullRegPath =
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

// Decode ROT13 sub key value
/**
 * NOTE: If NoEncrypt is a DWORD set to 1 under the UserAssist registry key, new
 * values are saved in plain text. This value (NoEncrypt) has to be manually
 * added to the UserAssist registry key.
 */
std::string rotDecode(std::string& value_key_reg) {
  std::string decoded_value_key;

  for (std::size_t i = 0; i < value_key_reg.size(); i++) {
    if (isalpha(value_key_reg[i])) {
      if (value_key_reg[i] >= 'a' && value_key_reg[i] <= 'm') {
        decoded_value_key.append(1, value_key_reg[i] + 13);
      } else if (value_key_reg[i] >= 'm' && value_key_reg[i] <= 'z') {
        decoded_value_key.append(1, value_key_reg[i] - 13);
      } else if (value_key_reg[i] >= 'A' && value_key_reg[i] <= 'M') {
        decoded_value_key.append(1, value_key_reg[i] + 13);
      } else if (value_key_reg[i] >= 'M' && value_key_reg[i] <= 'Z') {
        decoded_value_key.append(1, value_key_reg[i] - 13);
      }
    } else {
      decoded_value_key.append(1, value_key_reg[i]);
    }
  }
  return decoded_value_key;
}

// Convert little endian Windows FILETIME to unix timestamp
long long littleEndianToUnixTime(const std::string& time_data) {
  // If timestamp is zero dont convert to UNIX Time
  if (time_data == "0000000000000000") {
    return 0LL;
  } else {
    std::string time_string = time_data;
    // swap endianess
    std::reverse(time_string.begin(), time_string.end());

    for (std::size_t i = 0; i < time_string.length(); i += 2) {
      char temp = time_string[i];
      time_string[i] = time_string[i + 1];
      time_string[i + 1] = temp;
    }

    // Convert string to long long
    unsigned long long last_run =
        tryTo<unsigned long long>(time_string, 16).takeOr(0ull);
    if (last_run == 0ull) {
      LOG(WARNING) << "Failed to convert string to long long: " << time_string;
      return 0LL;
    }

    FILETIME file_time;
    ULARGE_INTEGER large_time;
    large_time.QuadPart = last_run;
    file_time.dwHighDateTime = large_time.HighPart;
    file_time.dwLowDateTime = large_time.LowPart;
    auto last_time = filetimeToUnixtime(file_time);
    return last_time;
  }
}

// Get execution count
std::size_t executionNum(const std::string& assist_data) {
  if (assist_data.length() <= 16) {
    LOG(WARNING) << "Userassist execution count format is incorrect";
    return -1;
  }

  std::string execution_count = assist_data.substr(8, 8);

  // swap endianess
  std::reverse(execution_count.begin(), execution_count.end());

  for (std::size_t i = 0; i < execution_count.length(); i += 2) {
    char temp = execution_count[i];
    execution_count[i] = execution_count[i + 1];
    execution_count[i + 1] = temp;
  }

  auto count = tryTo<std::size_t>(execution_count, 16);
  if (count.isError()) {
    LOG(WARNING) << "Error getting execution count: " << count.takeError();
    return -1;
  }
  return count.get();
}

QueryData genUserAssist(QueryContext& context) {
  QueryData results;
  QueryData users;

  queryKey("HKEY_USERS", users);

  for (const auto& uKey : users) {
    auto keyType = uKey.find("type");
    auto keyPath = uKey.find("path");
    if (keyType == uKey.end() || keyPath == uKey.end()) {
      continue;
    }

    std::string fullPath = keyPath->second + kFullRegPath;
    QueryData user_assist_results;
    queryKey(fullPath, user_assist_results);

    for (const auto& rKey : user_assist_results) {
      auto keyType = rKey.find("type");
      auto keyPath = rKey.find("path");
      if (keyType == rKey.end() || keyPath == rKey.end()) {
        continue;
      }
      std::string full_path_key = keyPath->second + "\\Count";

      QueryData assist_results;
      queryKey(full_path_key, assist_results);

      for (const auto& aKey : assist_results) {
        std::string subkey = aKey.at("path");

        // split reg path by \Count\ to get Key values
        auto count_key = subkey.find("Count\\");
        auto value_key = subkey.substr(count_key);
        auto value_key_reg = value_key.substr(6, std::string::npos);

        std::string decoded_value_key = rotDecode(value_key_reg);
        Row r;

        // set UEME_CTLCUACount:ctor and UEME_CTLSESSION values to blank they
        // are not executables
        if (decoded_value_key == "UEME_CTLCUACount:ctor" ||
            decoded_value_key == "UEME_CTLSESSION") {
          r["path"] = decoded_value_key;
          r["last_execution_time"] = "";
          r["count"] = "";
          r["sid"] = uKey.at("name");
          results.push_back(r);
        } else {
          std::string assist_data = aKey.at("data");
          auto time_str = 0LL;
          if (assist_data.length() <= 136) {
            LOG(WARNING)
                << "Userassist last execute Timestamp format is incorrect";
          } else {
            std::string time_data = assist_data.substr(120, 16);
            time_str = littleEndianToUnixTime(time_data);
          }

          r["path"] = decoded_value_key;

          if (time_str == 0LL) {
            r["count"] = "";
            r["last_execution_time"] = "";
          } else {
            r["last_execution_time"] = INTEGER(time_str);
            auto count = executionNum(assist_data);
            r["count"] = INTEGER(count);
          }
          r["sid"] = uKey.at("name");
          results.push_back(r);
        }
      }
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery

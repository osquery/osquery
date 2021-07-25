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
#include <osquery/utils/rot13.h>

#include <string>

namespace osquery {
namespace tables {

constexpr auto kFullRegPath =
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

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
        std::string value_key_reg = value_key.substr(6, std::string::npos);

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
            // Sometimes Userassist artifacts have 0 as timestamp, if so skip
            // filetime conversion
            time_str = (time_data == "0000000000000000")
                           ? 0LL
                           : littleEndianToUnixTime(time_data);
          }
          r["path"] = decoded_value_key;

          if (time_str == 0LL) {
            r["count"] = "";
          } else {
            auto count = executionNum(assist_data);
            r["count"] = INTEGER(count);
          }
          r["last_execution_time"] = BIGINT(time_str);
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

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/system/time.h>
#include <string>

namespace osquery {
namespace tables {

// Decode ROT13 sub key value
std::string rot_decode(std::string value_key_reg) {
  std::string decoded_value_key;

  for (size_t i = 0; i < value_key_reg.size(); i++) {
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

QueryData genUserAssist(QueryContext& context) {
  QueryData results;
  QueryData users;

  queryKey("HKEY_USERS", users);

  for (const auto& uKey : users) {
    if (uKey.count("type") == 0 || uKey.count("path") == 0) {
      continue;
    }

    std::string path = uKey.at("path");
    std::string fullPath = path.append(
        "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");

    QueryData user_assist_results;
    queryKey(fullPath, user_assist_results);

    for (const auto& rKey : user_assist_results) {
      if (rKey.count("type") == 0 || rKey.count("path") == 0) {
        continue;
      }
      std::string path_key = rKey.at("path");
      std::string full_path_key = path_key.append("\\Count");

      QueryData assist_results;
      queryKey(full_path_key, assist_results);

      for (const auto& aKey : assist_results) {
        std::string subkey = aKey.at("path");

        // split reg path by \Count\ to get Key values
        std::size_t count_key = subkey.find("Count\\");
        std::string value_key = subkey.substr(count_key);
        std::string value_key_reg = value_key.substr(6, std::string::npos);

        std::string decoded_value_key = rot_decode(value_key_reg);

        Row r;

        // set UEME_CTLCUACount:ctor and UEME_CTLSESSION values to blank they
        // are not executables
        if (decoded_value_key == "UEME_CTLCUACount:ctor" ||
            decoded_value_key == "UEME_CTLSESSION") {
          r["path"] = decoded_value_key;
          r["last_execution_time"] = "";
          r["count"] = INTEGER("");
          r["sid"] = uKey.at("name");
          results.push_back(r);
        } else {
          std::string assist_data = aKey.at("data");
          std::string execution_count = assist_data.substr(8, 8);

          // swap endianess
          std::reverse(execution_count.begin(), execution_count.end());

          char temp;
          for (int i = 0; i < execution_count.length(); i += 2) {
            temp = execution_count[i];
            execution_count[i] = execution_count[i + 1];
            execution_count[i + 1] = temp;
          }

          int count = (int)strtol(execution_count.c_str(), 0, 16);

          std::string last_run_string = assist_data.substr(120, 16);

          // swap endianess
          std::reverse(last_run_string.begin(), last_run_string.end());

          for (int i = 0; i < last_run_string.length(); i += 2) {
            temp = last_run_string[i];
            last_run_string[i] = last_run_string[i + 1];
            last_run_string[i + 1] = temp;
          }

          // Convert Windows FILETIME to UNIX Time
          unsigned long long last_run =
              std::stoull(last_run_string.c_str(), 0, 16);
          last_run = (last_run / 10000000) - 11644473600;

          std::time_t last_run_time = (int)last_run;

          struct tm tm;
          gmtime_s(&tm, &last_run_time);

          auto time_str = platformAsctime(&tm);

          r["path"] = decoded_value_key;
          r["last_execution_time"] = time_str;
          r["count"] = INTEGER(count);
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

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstddef>
#include <string>
#include <string_view>

#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/applications/ai_assistant_chats/utils.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kUserRole{"user"};
const std::string kAssistantRole{"assistant"};

namespace {

/**
 * A timestamp at least this large cannot be seconds since the epoch (it
 * would land past the year 5000), so it is milliseconds. The stores this
 * table reads use both units, sometimes within the same application.
 */
const std::int64_t kMillisecondsThreshold{100000000000LL};

} // namespace

/// Returns the named string member of an object, or an empty string.
std::string stringMember(const rapidjson::Value& object, const char* name) {
  if (!object.IsObject()) {
    return "";
  }

  auto it = object.FindMember(name);
  if (it == object.MemberEnd() || !it->value.IsString()) {
    return "";
  }

  return it->value.GetString();
}
/**
 * @brief Checks whether a JSON object member is set to true.
 *
 * @param object JSON value containing the member.
 * @param name Member name to inspect.
 * @return true if the named member is a boolean set to true, false otherwise.
 */
bool boolMember(const rapidjson::Value& object, const char* name) {
  if (!object.IsObject()) {
    return false;
  }

  auto it = object.FindMember(name);
  return it != object.MemberEnd() && it->value.IsBool() && it->value.GetBool();
}
/**
 * @brief Reads a timestamp member and converts it to Unix seconds.
 *
 * The member may contain an ISO 8601 string or a numeric timestamp in seconds
 * or milliseconds since the Unix epoch.
 *
 * @return Unix timestamp in seconds, or 0 for missing, invalid, negative, or
 * unsupported values.
 */
std::int64_t timestampMember(const rapidjson::Value& object, const char* name) {
  if (!object.IsObject()) {
    return 0;
  }

  auto it = object.FindMember(name);
  if (it == object.MemberEnd()) {
    return 0;
  }

  if (it->value.IsString()) {
    return iso8601ToUnixTime(it->value.GetString());
  }

  if (it->value.IsNumber()) {
    auto value = static_cast<std::int64_t>(it->value.GetDouble());
    if (value < 0) {
      return 0;
    }
    return value >= kMillisecondsThreshold ? value / 1000 : value;
  }

  return 0;
}
/**
 * @brief Determines the per-user application-data directory for the current
 * platform.
 *
 * @param home User's home directory.
 * @return Path to the platform-specific application-data directory.
 */
fs::path appDataRoot(const fs::path& home) {
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    return home / "AppData" / "Roaming";
  }

  if (isPlatform(PlatformType::TYPE_OSX)) {
    return home / "Library" / "Application Support";
  }

  return home / ".config";
}
/**
 * @brief Processes a JSON Lines file one entry at a time.
 *
 * Invokes the handler for each newline-delimited entry and for any final
 * unterminated entry after a successful read.
 *
 * @param path Path to the JSON Lines file.
 * @param handler Callback invoked with each entry.
 * @return Status of the file-reading operation.
 */
Status readJsonLines(const std::string& path,
                     const std::function<void(const std::string&)>& handler) {
  std::string pending;
  auto status = readFile(path, [&](std::string_view chunk) {
    pending.append(chunk.data(), chunk.size());

    std::size_t start = 0;
    for (auto end = pending.find('\n'); end != std::string::npos;
         end = pending.find('\n', start)) {
      handler(pending.substr(start, end - start));
      start = end + 1;
    }

    pending.erase(0, start);
  });

  if (status.ok()) {
    handler(pending);
  }

  return status;
}
/**
 * @brief Converts an ISO 8601 date and time to Unix time.
 *
 * @param iso_time Timestamp in `YYYY-MM-DDTHH:MM:SS` or space-separated form,
 *                 optionally followed by fractional seconds or `Z`.
 * @return std::int64_t Unix time in seconds, or `0` for invalid timestamps.
 */
std::int64_t iso8601ToUnixTime(const std::string& iso_time) {
  // Expected shape: YYYY-MM-DDTHH:MM:SS, optionally followed by fractional
  // seconds and a "Z". Anything else is not a timestamp this table knows
  // how to read.
  if (iso_time.size() < 19 || iso_time[4] != '-' || iso_time[7] != '-' ||
      (iso_time[10] != 'T' && iso_time[10] != ' ') || iso_time[13] != ':' ||
      iso_time[16] != ':') {
    return 0;
  }

  auto field = [&iso_time](std::size_t offset,
                           std::size_t length) -> std::int64_t {
    auto value = tryTo<std::int64_t>(iso_time.substr(offset, length), 10);
    return value.isValue() ? value.get() : -1;
  };

  auto year = field(0, 4);
  auto month = field(5, 2);
  auto day = field(8, 2);
  auto hour = field(11, 2);
  auto minute = field(14, 2);
  auto second = field(17, 2);

  if (year < 0 || month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 ||
      hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
    return 0;
  }

  // Days since the epoch, counting from a year that starts in March so
  // that a leap day falls at the end of it and never has to be special
  // cased. 719468 is the number of days between that calendar's origin
  // and 1970-01-01, and 146097 is the number of days in 400 years.
  auto shifted_year = year - (month <= 2 ? 1 : 0);
  auto era = (shifted_year >= 0 ? shifted_year : shifted_year - 399) / 400;
  auto year_of_era = shifted_year - era * 400;
  auto day_of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
  auto day_of_era =
      year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  auto days = era * 146097 + day_of_era - 719468;

  return days * 86400 + hour * 3600 + minute * 60 + second;
}

} // namespace tables
} // namespace osquery

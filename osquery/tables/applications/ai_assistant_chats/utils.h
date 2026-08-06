/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/utils/json/json.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace tables {

/// A single chat message, one row of the ai_assistant_chats table.
struct AIAssistantChat final {
  std::string application;
  std::string session_id;
  std::string role;
  std::string message;
  std::int64_t timestamp{0};
  std::string path;
};

/// The two authors a message can have.
extern const std::string kUserRole;
extern const std::string kAssistantRole;

/**
 * @brief Convert an ISO 8601 UTC timestamp into Unix time.
 *
 * Handles "2026-05-03T07:59:23.977Z" and the same value without the
 * fractional seconds and/or the trailing "Z". The value is always read as
 * UTC, which is what every store this table parses writes. Returns 0 for
 * anything that does not have that shape, so callers can treat 0 as
 * "no timestamp recorded".
 */
std::int64_t iso8601ToUnixTime(const std::string& iso_time);

/// Returns the named string member of an object, or an empty string.
std::string stringMember(const rapidjson::Value& object, const char* name);

/// Returns whether the named member is present and set to true.
bool boolMember(const rapidjson::Value& object, const char* name);

/**
 * @brief Returns the named timestamp member as Unix time.
 *
 * The member may be an ISO 8601 string or a number of seconds or
 * milliseconds since the epoch, depending on which application wrote it.
 * Returns 0 when there is no timestamp to read.
 */
std::int64_t timestampMember(const rapidjson::Value& object, const char* name);

/// Returns the root each application keeps its per-user data under.
boost::filesystem::path appDataRoot(const boost::filesystem::path& home);

/**
 * @brief Streams a JSON lines file, one entry at a time to `handler`.
 *
 * A long session's file reaches tens of megabytes, so entries are split
 * out of it as it streams in rather than holding the whole thing in
 * memory at once.
 */
Status readJsonLines(const std::string& path,
                     const std::function<void(const std::string&)>& handler);

} // namespace tables
} // namespace osquery

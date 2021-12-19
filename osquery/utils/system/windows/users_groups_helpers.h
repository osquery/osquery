/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include <osquery/utils/system/system.h>

#include <LM.h>

namespace osquery {

auto net_api_free = [](LPVOID pointer) { NetApiBufferFree(pointer); };
using users_info_0_t = std::unique_ptr<LPUSER_INFO_0, decltype(net_api_free)>;

/**
 * @brief Windows helper function used by to convert a binary SID struct into
 * a string.
 *
 * @returns string representation of the binary SID struct.
 */
std::string psidToString(PSID sid);

/**
 * @brief Windows helper function to lookup a SID from a username
 *
 * @returns a unique_ptr to a PSID
 */
std::unique_ptr<BYTE[]> getSidFromAccountName(const std::wstring& account_name);

/**
 * @brief Get the relative identifier (RID) from a security identifier (SID).
 *
 * @returns the RID represented as an unsigned long integer.
 */
DWORD getRidFromSid(PSID sid);

std::optional<std::uint32_t> getGidFromUserSid(PSID sid);
std::optional<std::uint32_t> getGidFromUsername(LPCWSTR username);

std::string getGroupSidFromUserSid(PSID sid);
std::string getGroupSidFromUsername(const std::wstring& username);

std::unique_ptr<BYTE[]> getSidFromAccountName(LPCWSTR account_name);
std::string getUserHomeDir(const std::string& sid);
} // namespace osquery

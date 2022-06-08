/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "users_groups_helpers.h"

#include <set>
#include <vector>

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {

const std::set<int> kRegistryStringTypes = {
    REG_SZ, REG_MULTI_SZ, REG_EXPAND_SZ};

auto close_reg_handle = [](HKEY handle) { RegCloseKey(handle); };
using reg_handle_t = std::unique_ptr<HKEY__, decltype(close_reg_handle)>;

const std::wstring kRegProfileKey =
    L"SOFTWARE\\Microsoft\\Windows "
    "NT\\CurrentVersion\\ProfileList";
const std::wstring kProfileValueName = L"ProfileImagePath";
const wchar_t kRegSep = '\\';

std::unique_ptr<BYTE[]> getSidFromAccountName(LPCWSTR account_name) {
  if (account_name == nullptr || account_name[0] == 0) {
    VLOG(1) << "No account name provided";
    return nullptr;
  }

  // Call LookupAccountNameW() once to retrieve the necessary buffer sizes for
  // the SID (in bytes) and the domain name (in TCHARS):
  DWORD sid_buffer_size = 0;
  DWORD domain_name_size = 0;
  auto e_sid_type = SidTypeUnknown;
  auto ret = LookupAccountNameW(nullptr,
                                account_name,
                                nullptr,
                                &sid_buffer_size,
                                nullptr,
                                &domain_name_size,
                                &e_sid_type);

  if (ret == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    VLOG(1) << "Failed to lookup account name " << wstringToString(account_name)
            << " with " << GetLastError();
    return nullptr;
  }

  // Allocate buffers for the (binary data) SID and (wide string) domain name:
  auto sid_buffer = std::make_unique<BYTE[]>(sid_buffer_size);
  std::vector<wchar_t> domain_name(domain_name_size);

  // Call LookupAccountNameW() a second time to actually obtain the SID for
  // the given account name:
  ret = LookupAccountNameW(nullptr,
                           account_name,
                           sid_buffer.get(),
                           &sid_buffer_size,
                           domain_name.data(),
                           &domain_name_size,
                           &e_sid_type);
  if (ret == 0) {
    VLOG(1) << "Failed to lookup account name " << wstringToString(account_name)
            << " with " << GetLastError();
    return nullptr;
  } else if (IsValidSid(sid_buffer.get()) == FALSE) {
    VLOG(1) << "The SID for " << wstringToString(account_name)
            << " is invalid.";
  }

  // Implicit move operation. Caller "owns" returned pointer:
  return sid_buffer;
}

std::unique_ptr<BYTE[]> getSidFromAccountName(
    const std::wstring& account_name) {
  return getSidFromAccountName(account_name.data());
}

std::string psidToString(PSID sid) {
  LPSTR sid_out = nullptr;
  auto ret = ConvertSidToStringSidA(sid, &sid_out);
  if (ret == 0) {
    VLOG(1) << "ConvertSidToString failed with " << GetLastError();
    return {};
  }
  std::string sid_string(sid_out);
  LocalFree(sid_out);
  return sid_string;
}

std::string getGroupSidFromUsername(LPCWSTR username) {
  WORD level = 0;
  DWORD flags = 0;
  DWORD pref_max_len = MAX_PREFERRED_LENGTH;
  DWORD entries_read = 0;
  DWORD total_entries = 0;
  std::unique_ptr<BYTE[]> sid_smart_ptr = nullptr;
  PSID sid_ptr = nullptr;

  LPLOCALGROUP_USERS_INFO_0 user_groups_buff = nullptr;
  auto user_groups_buff_deleter = scope_guard::create([&user_groups_buff]() {
    if (!user_groups_buff) {
      NetApiBufferFree(user_groups_buff);
    }
  });

  auto ret = NetUserGetLocalGroups(nullptr,
                                   username,
                                   level,
                                   flags,
                                   (LPBYTE*)&user_groups_buff,
                                   pref_max_len,
                                   &entries_read,
                                   &total_entries);

  if (ret != NERR_Success) {
    VLOG(1) << "Failed to get the local groups of "
            << wstringToString(username);
    return {};
  }

  if (user_groups_buff == nullptr) {
    return {};
  }

  LPWSTR sid_string;

  // A user often has more than one local group. We only return the first!
  sid_smart_ptr = getSidFromAccountName(user_groups_buff->lgrui0_name);

  if (sid_smart_ptr == nullptr) {
    VLOG(1) << "Sid smartptr null";
    return {};
  }

  sid_ptr = static_cast<PSID>(sid_smart_ptr.get());

  auto convert_res = ConvertSidToStringSidW(sid_ptr, &sid_string);

  if (!convert_res) {
    VLOG(1) << "Failed to convert sid to string";
    return {};
  }

  return wstringToString(sid_string);
}

std::string getGroupSidFromUsername(const std::wstring& username) {
  return getGroupSidFromUsername(username.data());
}

std::string getGroupSidFromUserSid(PSID sid) {
  auto e_sid_type = SidTypeUnknown;
  DWORD username_size = 0;
  DWORD domain_name_size = 1;

  LookupAccountSidW(nullptr,
                    sid,
                    nullptr,
                    &username_size,
                    nullptr,
                    &domain_name_size,
                    &e_sid_type);
  std::vector<wchar_t> username(username_size);
  std::vector<wchar_t> domain_name(domain_name_size);
  auto account_found = LookupAccountSidW(nullptr,
                                         sid,
                                         username.data(),
                                         &username_size,
                                         domain_name.data(),
                                         &domain_name_size,
                                         &e_sid_type);
  if (!account_found) {
    VLOG(1) << "Failed to find an account!";
    return {};
  }

  return getGroupSidFromUsername(username.data());
}

std::optional<std::uint32_t> getGidFromUsername(LPCWSTR username) {
  // Use NetUserGetLocalGroups to get a Local Group GID for this user
  WORD level = 0;
  DWORD flags = 0;
  DWORD pref_max_len = MAX_PREFERRED_LENGTH;
  DWORD entries_read = 0;
  DWORD total_entries = 0;
  std::unique_ptr<BYTE[]> sid_smart_ptr = nullptr;
  PSID sid = nullptr;
  LPLOCALGROUP_USERS_INFO_0 user_groups_buff = nullptr;

  auto ret = NetUserGetLocalGroups(nullptr,
                                   username,
                                   level,
                                   flags,
                                   reinterpret_cast<LPBYTE*>(&user_groups_buff),
                                   pref_max_len,
                                   &entries_read,
                                   &total_entries);

  std::optional<std::uint32_t> gid;

  if (ret == NERR_Success) {
    // A user often has more than one local group. We only return the first!
    if (user_groups_buff != nullptr) {
      auto group_sid_ptr = getSidFromAccountName(user_groups_buff->lgrui0_name);
      if (group_sid_ptr) {
        gid = getRidFromSid(group_sid_ptr.get());
      }
      NetApiBufferFree(user_groups_buff);
      return gid;
    }
  }

  NetApiBufferFree(user_groups_buff);

  LPUSER_INFO_3 user_buff = nullptr;

  /* If none of the above worked, the user may not have a Local Group.
     Fallback to using the primary group id from its USER_INFO_3 struct */
  DWORD user_info_level = 3;
  ret = NetUserGetInfo(nullptr,
                       username,
                       user_info_level,
                       reinterpret_cast<LPBYTE*>(&user_buff));
  if (ret == NERR_Success) {
    gid = user_buff->usri3_primary_group_id;
  }

  NetApiBufferFree(user_buff);

  return gid;
}

std::optional<std::uint32_t> getGidFromUserSid(PSID sid) {
  auto e_use = SidTypeUnknown;
  DWORD username_size = 0;
  DWORD domain_name_size = 1;

  // LookupAccountSid first gets the size of the name buff required
  LookupAccountSidW(nullptr,
                    sid,
                    nullptr,
                    &username_size,
                    nullptr,
                    &domain_name_size,
                    &e_use);
  std::vector<wchar_t> username_buffer(username_size);
  std::vector<wchar_t> domain_name(domain_name_size);
  auto account_found = LookupAccountSidW(nullptr,
                                         sid,
                                         username_buffer.data(),
                                         &username_size,
                                         domain_name.data(),
                                         &domain_name_size,
                                         &e_use);

  if (account_found == 0) {
    return {};
  }

  return getGidFromUsername(username_buffer.data());
}

DWORD getRidFromSid(PSID sid) {
  BYTE* count_ptr = GetSidSubAuthorityCount(sid);
  DWORD index_of_rid = static_cast<DWORD>(*count_ptr - 1);
  DWORD* rid_ptr = GetSidSubAuthority(sid, index_of_rid);
  return *rid_ptr;
}

std::string getUserHomeDir(const std::string& sid) {
  std::wstring profile_key_path = kRegProfileKey;
  profile_key_path += kRegSep;
  profile_key_path += stringToWstring(sid);

  HKEY hkey;
  auto ret = RegOpenKeyExW(
      HKEY_LOCAL_MACHINE, profile_key_path.c_str(), 0, KEY_READ, &hkey);

  if (ret != ERROR_SUCCESS) {
    if (ret != ERROR_FILE_NOT_FOUND) {
      VLOG(1) << "Failed to open " << wstringToString(profile_key_path)
              << " with error " << ret;
    }
    return {};
  }

  reg_handle_t registry_handle(hkey, close_reg_handle);
  DWORD values_count;
  DWORD max_value_data_length;

  ret = RegQueryInfoKeyW(registry_handle.get(),
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr,
                         &values_count,
                         nullptr,
                         &max_value_data_length,
                         nullptr,
                         nullptr);
  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "Failed to query key info " << wstringToString(profile_key_path)
            << " with error " << ret;
    return {};
  }

  if (values_count == 0) {
    return {};
  }

  DWORD value_type;
  DWORD value_data_length;
  std::wstring value_data;
  value_data.resize(max_value_data_length);

  value_data_length = max_value_data_length;

  ret = RegQueryValueExW(registry_handle.get(),
                         kProfileValueName.c_str(),
                         nullptr,
                         &value_type,
                         reinterpret_cast<LPBYTE>(value_data.data()),
                         &value_data_length);

  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "Failed to query value " << wstringToString(kProfileValueName)
            << " for key " << wstringToString(profile_key_path)
            << " with error " << ret;
    return {};
  }

  if (kRegistryStringTypes.find(value_type) == kRegistryStringTypes.end()) {
    VLOG(1) << "Value " << wstringToString(kProfileValueName) << " in key "
            << wstringToString(profile_key_path) << " is not a string";
    return {};
  }

  return wstringToString(value_data);
}
} // namespace osquery

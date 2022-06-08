/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "users_service.h"

#include <chrono>
#include <string>
#include <thread>

#include <LM.h>

#include <osquery/core/shutdown.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {

const std::wstring kRegProfileKey =
    L"SOFTWARE\\Microsoft\\Windows "
    "NT\\CurrentVersion\\ProfileList";
const std::set<std::string> kWellKnownSids = {
    "S-1-5-1",
    "S-1-5-2",
    "S-1-5-3",
    "S-1-5-4",
    "S-1-5-6",
    "S-1-5-7",
    "S-1-5-8",
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-12",
    "S-1-5-13",
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-21",
    "S-1-5-32",
};

/* How many users to process before a delay is introduced
   when updating the cache */
constexpr std::uint32_t kUsersBatch = 100;

FLAG(uint32,
     users_service_delay,
     250,
     "Delay in milliseconds between each batch of users that is "
     "retrieved from the system");

FLAG(uint32,
     users_service_interval,
     1800,
     "Interval in seconds between users cache updates");

auto close_reg_handle = [](HKEY handle) { RegCloseKey(handle); };
using reg_handle_t = std::unique_ptr<HKEY__, decltype(close_reg_handle)>;

std::optional<std::vector<std::string>> getRoamingProfileSids() {
  HKEY hkey;
  auto ret = RegOpenKeyExW(
      HKEY_LOCAL_MACHINE, kRegProfileKey.c_str(), 0, KEY_READ, &hkey);

  if (ret != ERROR_SUCCESS) {
    return std::nullopt;
  }

  reg_handle_t registry_handle(hkey, close_reg_handle);

  const auto max_key_length = 255;
  DWORD subkeys_count;
  DWORD max_name_length;
  DWORD ret_code;

  ret_code = RegQueryInfoKeyW(registry_handle.get(),
                              nullptr,
                              nullptr,
                              nullptr,
                              &subkeys_count,
                              nullptr,
                              nullptr,
                              nullptr,
                              &max_name_length,
                              nullptr,
                              nullptr,
                              nullptr);
  if (ret_code != ERROR_SUCCESS) {
    return std::nullopt;
  }

  if (subkeys_count == 0) {
    return {};
  }

  std::wstring key_name;
  key_name.resize(max_key_length);

  std::vector<std::string> subkeys_names;

  // Process registry subkeys
  for (DWORD i = 0; i < subkeys_count; i++) {
    ret_code =
        RegEnumKeyW(registry_handle.get(), i, key_name.data(), max_key_length);
    if (ret_code != ERROR_SUCCESS) {
      return std::nullopt;
    }

    subkeys_names.emplace_back(wstringToString(key_name));
  }

  return subkeys_names;
}

UsersService::UsersService(std::promise<void> users_cache_promise,
                           std::shared_ptr<UsersCache> users_cache)
    : InternalRunnable("UsersService"),
      users_cache_promise_(std::move(users_cache_promise)),
      users_cache_{users_cache} {}

void UsersService::start() {
  std::set<std::string> processed_sids;

  // Initialize the cache all in one step
  {
    std::vector<User> cache_init;
    auto update_user_func = [&cache_init](User user) {
      cache_init.emplace_back(std::move(user));
    };
    processLocalAccounts(processed_sids, update_user_func);
    processRoamingProfiles(processed_sids, update_user_func);

    users_cache_->initializeCache(std::move(cache_init));

    // Signal that the cache is now initialized
    users_cache_promise_.set_value();
    VLOG(1) << "Users cache initialized";
  }

  // Switch the update function so that we update users one at a time
  auto update_user_func = [this](User user) {
    users_cache_->updateUser(std::move(user));
  };

  while (!interrupted()) {
    pause(std::chrono::milliseconds(FLAGS_users_service_interval * 1000));

    if (interrupted()) {
      break;
    }

    processLocalAccounts(processed_sids, update_user_func);
    processRoamingProfiles(processed_sids, update_user_func);
    users_cache_->increaseGeneration();
    users_cache_->cleanupExpiredUsers();
  }
}

// Enumerate all local users, constraining results to the list of UIDs if
// any, and recording all enumerated users' SIDs to exclude later from the
// walk of the Roaming Profiles key in the registry.
void UsersService::processLocalAccounts(
    std::set<std::string>& processed_sids,
    std::function<UpdateUserFunc> update_user_func) {
  // Enumerate the users by only the usernames (level 0 struct) and then
  // get the desired level of info for each (level 4 struct includes SIDs).
  DWORD user_info_level = 0;
  DWORD detailed_user_info_level = 4;
  DWORD num_users_read = 0;
  DWORD total_users = 0;
  DWORD resume_handle = 0;
  DWORD ret = 0;
  LPUSER_INFO_0 users_info_buffer = nullptr;

  do {
    ret = NetUserEnum(nullptr,
                      user_info_level,
                      FILTER_NORMAL_ACCOUNT,
                      reinterpret_cast<LPBYTE*>(&users_info_buffer),
                      MAX_PREFERRED_LENGTH,
                      &num_users_read,
                      &total_users,
                      &resume_handle);

    if (ret != NERR_Success && ret != ERROR_MORE_DATA) {
      VLOG(1) << "NetUserEnum failed with return value " << ret;
      break;
    }

    if (users_info_buffer == nullptr) {
      VLOG(1) << "NetUserEnum user buffer is null";
      break;
    }

    int users_updated_since_sleep = 0;
    for (DWORD i = 0; i < num_users_read; ++i) {
      LPUSER_INFO_0 user_info_lvl0 = &users_info_buffer[i];

      LPUSER_INFO_4 user_info_lvl4 = nullptr;
      ret = NetUserGetInfo(nullptr,
                           user_info_lvl0->usri0_name,
                           detailed_user_info_level,
                           reinterpret_cast<LPBYTE*>(&user_info_lvl4));

      if (ret != NERR_Success || user_info_lvl4 == nullptr) {
        if (user_info_lvl4 != nullptr) {
          NetApiBufferFree(user_info_lvl4);
        }

        VLOG(1) << "Failed to get additional information for the user "
                << wstringToString(user_info_lvl0->usri0_name)
                << " with error code " << ret;
        continue;
      }

      User new_user;

      PSID sid = user_info_lvl4->usri4_user_sid;
      std::string sid_string = psidToString(sid);
      processed_sids.insert(sid_string);

      new_user.username = wstringToString(user_info_lvl4->usri4_name);
      new_user.uid = getRidFromSid(sid);

      /* NOTE: This still keeps the old behavior where if getting the gid
         from the first local group or the primary group id fails,
         then we use the uid of the user. */
      new_user.gid =
          getGidFromUsername(user_info_lvl4->usri4_name).value_or(new_user.uid);
      new_user.description = wstringToString(user_info_lvl4->usri4_comment);
      new_user.directory = getUserHomeDir(sid_string);
      new_user.type = "local";
      new_user.sid = std::move(sid_string);
      NetApiBufferFree(user_info_lvl4);

      update_user_func(std::move(new_user));
      ++users_updated_since_sleep;

      // Slow down users processing
      if (users_updated_since_sleep == kUsersBatch &&
          (i + 1) < num_users_read) {
        users_updated_since_sleep = 0;

        pause(std::chrono::milliseconds(FLAGS_users_service_delay));

        if (interrupted()) {
          ret = NERR_Success;
          break;
        }
      }
    }
  } while (ret == ERROR_MORE_DATA);
} // namespace

// Enumerate the users from the profiles key in the Registry, matching only
// the UIDs/RIDs (if any) and skipping any SIDs of local-only users that
// were already processed in the earlier API-based enumeration.
void UsersService::processRoamingProfiles(
    const std::set<std::string>& processed_sids,
    std::function<UpdateUserFunc> update_user_func) {
  auto opt_roaming_profile_sids = getRoamingProfileSids();

  if (!opt_roaming_profile_sids.has_value()) {
    return;
  }

  for (const auto& profile_sid : *opt_roaming_profile_sids) {
    // Skip this user if already processed
    if (processed_sids.find(profile_sid) != processed_sids.end()) {
      continue;
    }

    User new_user;

    new_user.sid = profile_sid;
    new_user.type = kWellKnownSids.find(profile_sid) == kWellKnownSids.end()
                        ? "roaming"
                        : "special";

    PSID sid;
    auto ret = ConvertStringSidToSidA(profile_sid.c_str(), &sid);
    if (ret == FALSE) {
      VLOG(1) << "Converting SIDstring to SID failed with " << GetLastError();
      continue;
    } else {
      new_user.uid = getRidFromSid(sid);
      new_user.directory = getUserHomeDir(profile_sid);

      wchar_t account_name[UNLEN] = {0};
      wchar_t domain_name[DNLEN] = {0};
      DWORD account_name_length = UNLEN;
      DWORD domain_name_length = DNLEN;
      SID_NAME_USE e_use;
      ret = LookupAccountSidW(nullptr,
                              sid,
                              account_name,
                              &account_name_length,
                              domain_name,
                              &domain_name_length,
                              &e_use);

      LocalFree(sid);

      if (ret != FALSE) {
        new_user.username = wstringToString(account_name);
        /* NOTE: This still keeps the old behavior where if getting the gid
        from the first local group or the primary group id fails,
        then we use the uid of the user. */
        new_user.gid = getGidFromUsername(account_name).value_or(new_user.uid);
      } else {
        new_user.gid = -1;
      }

      // Also attempt to get the user account description comment. Move on if
      // NetUserGetInfo returns an error, as it will for some system accounts.
      DWORD basic_user_info_level = 2;
      LPUSER_INFO_2 user_info_lvl2 = nullptr;
      ret = NetUserGetInfo(nullptr,
                           account_name,
                           basic_user_info_level,
                           reinterpret_cast<LPBYTE*>(&user_info_lvl2));

      if (ret == NERR_Success && user_info_lvl2 != nullptr) {
        new_user.description = wstringToString(user_info_lvl2->usri2_comment);
        NetApiBufferFree(user_info_lvl2);
      }

      update_user_func(std::move(new_user));
    }
  }
}
}; // namespace osquery

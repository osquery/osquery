/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "groups_service.h"

#include <osquery/core/shutdown.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <LM.h>

namespace osquery {

/* How many groups to process before a delay is introduced
   when updating the cache */
constexpr std::uint32_t kGroupsBatch = 100;

FLAG(uint32,
     groups_service_delay,
     150,
     "Delay in milliseconds between each batch of groups that is "
     "retrieved from the system by the groups service");

FLAG(uint32,
     groups_service_interval,
     1800,
     "Interval in seconds between groups cache updates done by the groups "
     "service");

GroupsService::GroupsService(std::promise<void> groups_cache_promise,
                             std::shared_ptr<GroupsCache> groups_cache)
    : InternalRunnable("GroupsService"),
      groups_cache_promise_{std::move(groups_cache_promise)},
      groups_cache_{groups_cache} {}

void GroupsService::start() {
  {
    std::vector<Group> cache_init;
    auto update_user_func = [&cache_init](Group group) {
      cache_init.emplace_back(std::move(group));
    };

    processLocalGroups(update_user_func);

    groups_cache_->initializeCache(std::move(cache_init));

    // Signal that the cache is now initialized
    groups_cache_promise_.set_value();
    VLOG(1) << "Groups cache initialized";
  }

  auto update_user_func = [this](Group group) {
    groups_cache_->updateGroup(std::move(group));
  };

  while (!interrupted()) {
    pause(std::chrono::milliseconds(FLAGS_groups_service_interval * 1000));

    if (interrupted()) {
      break;
    }

    processLocalGroups(update_user_func);
    groups_cache_->increaseGeneration();
    groups_cache_->cleanupExpiredGroups();
  }
}

void GroupsService::processLocalGroups(
    std::function<UpdateGroupFunc> update_group_func) {
  DWORD group_info_level = 1;
  DWORD num_groups_read = 0;
  DWORD total_groups = 0;
  DWORD ret = 0;
  localgroup_info_1_ptr groups_info_buffer;

  do {
    ret = NetLocalGroupEnum(
        nullptr,
        group_info_level,
        reinterpret_cast<LPBYTE*>(groups_info_buffer.get_new_ptr()),
        MAX_PREFERRED_LENGTH,
        &num_groups_read,
        &total_groups,
        nullptr);

    if (ret != NERR_Success && ret != ERROR_MORE_DATA) {
      VLOG(1) << "NetLocalGroupEnum failed with return value: " << ret;
      break;
    }

    if (groups_info_buffer == nullptr) {
      VLOG(1) << "NetLocalGroupEnum groups buffer is null";
      break;
    }

    int groups_updated_since_sleep = 0;
    for (std::size_t i = 0; i < num_groups_read; i++) {
      PWSTR groupname = groups_info_buffer.get()[i].lgrpi1_name;
      auto sid_ptr = getSidFromAccountName(groupname);

      if (!sid_ptr) {
        // If we failed to find a SID, don't add a row to the table.
        VLOG(1) << "Failed to find a SID from LookupAccountNameW for group: "
                << wstringToString(groupname);
        continue;
      }

      const auto& group_sid = sid_ptr.get();

      Group new_group;
      new_group.sid = psidToString(group_sid);
      new_group.comment =
          wstringToString(groups_info_buffer.get()[i].lgrpi1_comment);
      new_group.gid = getRidFromSid(group_sid);
      new_group.groupname =
          wstringToString(groups_info_buffer.get()[i].lgrpi1_name);

      update_group_func(std::move(new_group));
      ++groups_updated_since_sleep;

      if (groups_updated_since_sleep == kGroupsBatch &&
          (i + 1) < num_groups_read) {
        groups_updated_since_sleep = 0;
        pause(std::chrono::milliseconds(FLAGS_groups_service_delay));
        if (interrupted()) {
          ret = NERR_Success;
          break;
        }
      }
    }

  } while (ret == ERROR_MORE_DATA);
}
} // namespace osquery

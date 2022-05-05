/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "global_users_groups_cache.h"

#include <osquery/core/shutdown.h>

namespace osquery {

std::shared_future<void> GlobalUsersGroupsCache::global_users_cache_future_;
std::shared_ptr<UsersCache> GlobalUsersGroupsCache::global_users_cache_ =
    std::make_shared<UsersCache>();

std::shared_future<void> GlobalUsersGroupsCache::global_groups_cache_future_;
std::shared_ptr<GroupsCache> GlobalUsersGroupsCache::global_groups_cache_ =
    std::make_shared<GroupsCache>();
;

const UsersCache& GlobalUsersGroupsCache::getUsersCache() {
  std::future_status status;
  do {
    status = global_users_cache_future_.wait_for(std::chrono::seconds(1));
  } while (status == std::future_status::timeout &&
           !osquery::shutdownRequested());

  return *global_users_cache_;
}

const GroupsCache& GlobalUsersGroupsCache::getGroupsCache() {
  std::future_status status;
  do {
    status = global_groups_cache_future_.wait_for(std::chrono::seconds(1));
  } while (status == std::future_status::timeout &&
           !osquery::shutdownRequested());

  return *global_groups_cache_;
}
} // namespace osquery

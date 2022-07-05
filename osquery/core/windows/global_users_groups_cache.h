/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <future>
#include <osquery/system/usersgroups/windows/users_groups_cache.h>

namespace osquery {
class GlobalUsersGroupsCache {
 public:
  /// Waits for the users cache to be initialized by the respective service
  /// and then returns a reference to it.
  static const UsersCache& getUsersCache();

  /// Waits for the groups cache to be initialized by the respective service
  /// and then returns a reference to it.
  static const GroupsCache& getGroupsCache();

 private:
  static std::shared_future<void> global_users_cache_future_;
  static std::shared_ptr<UsersCache> global_users_cache_;

  static std::shared_future<void> global_groups_cache_future_;
  static std::shared_ptr<GroupsCache> global_groups_cache_;

  friend class Initializer;
  friend void initUsersAndGroupsServices(bool, bool);
  friend void deinitUsersAndGroupsServices(bool, bool);
};
} // namespace osquery

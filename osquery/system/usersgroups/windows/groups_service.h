/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <functional>
#include <set>

#include <osquery/core/flags.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/system/usersgroups/windows/users_groups_cache.h>

namespace osquery {

class GroupsService : public InternalRunnable {
 public:
  GroupsService(std::promise<void> groups_cache_promise,
                std::shared_ptr<GroupsCache> groups_cache);

 protected:
  void start() override;

 private:
  using UpdateGroupFunc = void(Group user);

  void processLocalGroups(std::function<UpdateGroupFunc> update_group_func);

  std::promise<void> groups_cache_promise_;
  std::shared_ptr<GroupsCache> groups_cache_;
};
} // namespace osquery

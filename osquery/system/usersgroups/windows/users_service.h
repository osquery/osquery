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
#include <future>
#include <set>

#include <osquery/core/flags.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/system/usersgroups/windows/users_groups_cache.h>

namespace osquery {

class UsersService : public InternalRunnable {
 public:
  UsersService(std::promise<void> users_cache_promise,
               std::shared_ptr<UsersCache> users_cache);

 protected:
  void start() override;

 private:
  using UpdateUserFunc = void(User user);

  void processLocalAccounts(std::set<std::string>& processed_sids,
                            std::function<UpdateUserFunc> update_user_func);
  void processRoamingProfiles(const std::set<std::string>& processed_sids,
                              std::function<UpdateUserFunc> update_user_func);

  std::promise<void> users_cache_promise_;
  std::shared_ptr<UsersCache> users_cache_;
};
} // namespace osquery

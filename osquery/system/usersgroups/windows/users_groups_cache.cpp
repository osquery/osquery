/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "users_groups_cache.h"

namespace osquery {
void UsersCache::initializeCache(std::vector<User> initial_users) {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cached_users_ = std::move(initial_users);

  for (std::size_t i = 0; i < cached_users_.size(); ++i) {
    const auto& user = cached_users_[i];
    uid_cache_index_.emplace(user.uid, i);
    sid_cache_index_.emplace(user.sid, i);
  }
}

void UsersCache::updateUser(User user) {
  std::lock_guard<std::mutex> lock(cache_mutex_);

  user.generation = current_generation_ + 1;

  auto sid_it = sid_cache_index_.find(user.sid);
  if (sid_it != sid_cache_index_.end()) {
    cached_users_[sid_it->second] = std::move(user);

  } else {
    cached_users_.emplace_back(std::move(user));
    const auto& new_user = cached_users_.back();
    uid_cache_index_.emplace(new_user.uid, cached_users_.size() - 1);
    sid_cache_index_.emplace(new_user.sid, cached_users_.size() - 1);
  }
}

void UsersCache::increaseGeneration() {
  ++current_generation_;
}

void UsersCache::cleanupExpiredUsers() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cached_users_.erase(std::remove_if(cached_users_.begin(),
                                     cached_users_.end(),
                                     [this](const auto& user) {
                                       return user.generation <
                                              current_generation_;
                                     }),
                      cached_users_.end());

  current_generation_ = 0;

  uid_cache_index_.clear();
  sid_cache_index_.clear();

  for (std::size_t i = 0; i < cached_users_.size(); ++i) {
    auto& user = cached_users_[i];
    user.generation = 0;

    uid_cache_index_.emplace(user.uid, i);
    sid_cache_index_.emplace(user.sid, i);
  }
}

void UsersCache::clear() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  uid_cache_index_.clear();
  sid_cache_index_.clear();
  current_generation_ = 0;
  cached_users_.clear();
}

std::vector<User> UsersCache::getUsersByUid(std::uint32_t uid) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto user_range = uid_cache_index_.equal_range(uid);

  if (user_range.first == uid_cache_index_.end()) {
    return {};
  }

  std::vector<User> users;
  for (auto user_index_it = user_range.first;
       user_index_it != user_range.second;
       ++user_index_it) {
    users.emplace_back(cached_users_[user_index_it->second]);
  }

  return users;
}

std::optional<User> UsersCache::getUserBySid(const std::string& sid) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto user_it = sid_cache_index_.find(sid);

  if (user_it == sid_cache_index_.end()) {
    return std::nullopt;
  }

  auto user = cached_users_[user_it->second];

  return user;
}

std::vector<User> UsersCache::getAllUsers() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cached_users_;
}

void GroupsCache::initializeCache(std::vector<Group> initial_groups) {
  cached_groups_ = std::move(initial_groups);

  if (cached_groups_.size() > 0) {
    gid_cache_index_.reserve(cached_groups_.size());
    sid_cache_index_.reserve(cached_groups_.size());
    name_cache_index_.reserve(cached_groups_.size());
  }

  for (std::size_t i = 0; i < cached_groups_.size(); ++i) {
    const auto& group = cached_groups_[i];
    gid_cache_index_.emplace(group.gid, i);
    sid_cache_index_.emplace(group.sid, i);
    name_cache_index_.emplace(group.groupname, i);
  }
}

void GroupsCache::updateGroup(Group group) {
  std::lock_guard<std::mutex> lock(cache_mutex_);

  group.generation = current_generation_ + 1;

  auto sid_it = sid_cache_index_.find(group.sid);
  if (sid_it != sid_cache_index_.end()) {
    cached_groups_[sid_it->second] = std::move(group);

  } else {
    cached_groups_.emplace_back(std::move(group));
    const auto& new_group = cached_groups_.back();
    gid_cache_index_.emplace(new_group.gid, cached_groups_.size() - 1);
    sid_cache_index_.emplace(new_group.sid, cached_groups_.size() - 1);
    name_cache_index_.emplace(new_group.groupname, cached_groups_.size() - 1);
  }
}

void GroupsCache::increaseGeneration() {
  ++current_generation_;
}

void GroupsCache::cleanupExpiredGroups() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cached_groups_.erase(std::remove_if(cached_groups_.begin(),
                                      cached_groups_.end(),
                                      [this](const auto& group) {
                                        return group.generation <
                                               current_generation_;
                                      }),
                       cached_groups_.end());
  current_generation_ = 0;

  gid_cache_index_.clear();
  sid_cache_index_.clear();
  name_cache_index_.clear();

  for (std::size_t i = 0; i < cached_groups_.size(); ++i) {
    auto& group = cached_groups_[i];
    group.generation = 0;

    gid_cache_index_.emplace(group.gid, i);
    sid_cache_index_.emplace(group.sid, i);
    name_cache_index_.emplace(group.groupname, i);
  }
}

void GroupsCache::clear() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  gid_cache_index_.clear();
  sid_cache_index_.clear();
  name_cache_index_.clear();
  current_generation_ = 0;
  cached_groups_.clear();
}

std::vector<Group> GroupsCache::getGroupsByGid(std::uint32_t gid) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto group_range = gid_cache_index_.equal_range(gid);

  if (group_range.first == gid_cache_index_.end()) {
    return {};
  }

  std::vector<Group> groups;
  for (auto group_index_it = group_range.first;
       group_index_it != group_range.second;
       ++group_index_it) {
    groups.emplace_back(cached_groups_[group_index_it->second]);
  }

  return groups;
}

std::optional<Group> GroupsCache::getGroupBySid(const std::string& sid) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto group_it = sid_cache_index_.find(sid);

  if (group_it == sid_cache_index_.end()) {
    return std::nullopt;
  }

  return cached_groups_[group_it->second];
}

std::optional<Group> GroupsCache::getGroupByName(
    const std::string& name) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto group_it = name_cache_index_.find(name);

  if (group_it == name_cache_index_.end()) {
    return std::nullopt;
  }

  return cached_groups_[group_it->second];
}

std::vector<Group> GroupsCache::getAllGroups() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cached_groups_;
}
} // namespace osquery

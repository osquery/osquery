/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#include <osquery/utils/system/windows/users_groups_helpers.h>

namespace osquery {
struct User {
  std::uint32_t generation{0};
  std::uint32_t uid{std::numeric_limits<std::uint32_t>::max()};
  std::uint32_t gid{std::numeric_limits<std::uint32_t>::max()};
  std::string sid;
  std::string username;
  std::string description;
  std::string type;
  std::string directory;

  bool operator==(const User& other) const {
    return uid == other.uid && gid == other.gid && sid == other.sid &&
           username == other.username && description == other.description &&
           type == other.type && directory == other.directory;
  }
};

struct Group {
  std::uint32_t generation{0};
  std::uint32_t gid{std::numeric_limits<std::uint32_t>::max()};
  std::string sid;
  std::string groupname;
  std::string comment;

  bool operator==(const Group& other) const {
    return gid == other.gid && sid == other.sid &&
           groupname == other.groupname && comment == other.comment;
  }
};

using GidCacheIndex = std::unordered_multimap<DWORD, std::size_t>;
using UidCacheIndex = GidCacheIndex;
using SidCacheIndex = std::unordered_map<std::string, std::size_t>;
using GroupnameCacheIndex = std::unordered_map<std::string, std::size_t>;

class UsersCache {
 public:
  void initializeCache(std::vector<User> initial_users);

  /// Insert a new user or updates the user with the same sid
  /// This also sets the generation of the user to the next generation,
  /// so that it survives the cleanup.
  void updateUser(User user);

  /// Increases the generation of the cache.
  /// This is a mechanism used in conjuction with cleanupExpiredUsers
  /// to keep track of which users have been disappeared from the system.
  /// Call after doing a full update of the cache but before the cleanup.
  void increaseGeneration();

  /// Removes users from the cache that have not been seen since the last cache
  /// update. Internally compares the generation of the user against the current
  /// generation of the cache. If the user is of a lower generation,
  /// then it will be removed, because it means that is has not been seen again.
  /// Call this only after all the new set of users has been inserted,
  /// otherwise if called in between updates,
  /// more users than necessary will be removed.
  void cleanupExpiredUsers();

  /// Used for resetting the state of the cache for tests
  void clear();

  std::vector<User> getUsersByUid(std::uint32_t uid) const;
  std::optional<User> getUserBySid(const std::string& sid) const;
  std::vector<User> getAllUsers() const;

 private:
  UidCacheIndex uid_cache_index_;
  SidCacheIndex sid_cache_index_;
  std::vector<User> cached_users_;
  std::atomic<std::uint32_t> current_generation_{};
  mutable std::mutex cache_mutex_;
};

class GroupsCache {
 public:
  void initializeCache(std::vector<Group> initial_groups);

  /// Insert a new group or updates the group with the same sid
  /// This also sets the generation of the group to the next generation,
  /// so that it survives the cleanup.
  void updateGroup(Group group);

  /// Increases the generation of the cache.
  /// This is a mechanism used in conjuction with cleanupExpiredGroups
  /// to keep track of which groups have been disappeared from the system.
  /// Call after doing a full update of the cache but before the cleanup.
  void increaseGeneration();

  /// Removes groups from the cache that have not been seen since the last cache
  /// update. Internally compares the generation of the group against the
  /// current generation of the cache. If the group is of a lower generation,
  /// then it will be removed, because it means that is has not been seen again.
  /// Call this only after all the new set of groups has been inserted,
  /// otherwise if called in between updates,
  /// more groups than necessary will be removed.
  void cleanupExpiredGroups();

  /// Used for resetting the state of the cache for tests
  void clear();

  std::vector<Group> getGroupsByGid(std::uint32_t uid) const;
  std::optional<Group> getGroupBySid(const std::string& sid) const;
  std::optional<Group> getGroupByName(const std::string& name) const;
  std::vector<Group> getAllGroups() const;

 private:
  GidCacheIndex gid_cache_index_;
  SidCacheIndex sid_cache_index_;
  GroupnameCacheIndex name_cache_index_;
  std::vector<Group> cached_groups_;
  std::atomic<std::uint32_t> current_generation_{};
  mutable std::mutex cache_mutex_;
};
} // namespace osquery

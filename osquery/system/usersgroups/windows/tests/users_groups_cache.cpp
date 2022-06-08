/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/system/usersgroups/windows/users_groups_cache.h>

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

namespace osquery {

const std::vector<Group> kDefaultGroups{{0 /* generation */,
                                         456 /* gid */,
                                         "S-123-456" /* sid */,
                                         "test1" /* groupname */,
                                         "this is a test1" /* comment */},
                                        {0 /* generation */,
                                         457 /* gid */,
                                         "S-123-457" /* sid */,
                                         "test2" /* groupname */,
                                         "this is a test2" /* comment */},
                                        {0 /* generation */,
                                         458 /* gid */,
                                         "S-123-458" /* sid */,
                                         "test3" /* groupname */,
                                         "this is a test3" /* comment */}

};

const std::vector<User> kDefaultUsers{{0 /* generation */,
                                       456 /* uid */,
                                       1 /* gid */,
                                       "S-123-456" /* sid */,
                                       "test1" /* username */,
                                       "this is a test1" /* description */,
                                       "local" /* type */,
                                       "/home/test1" /* directory */},
                                      {0 /* generation */,
                                       457 /* uid */,
                                       2 /* gid */,
                                       "S-123-457" /* sid */,
                                       "test2" /* username */,
                                       "this is a test2" /* description */,
                                       "local" /* type */,
                                       "/home/test2" /* directory */},
                                      {0 /* generation */,
                                       458 /* uid */,
                                       3 /* gid */,
                                       "S-123-458" /* sid */,
                                       "test3" /* username */,
                                       "this is a test3" /* description */,
                                       "local" /* type */,
                                       "/home/test3" /* directory */}};

class UsersGroupsCacheTests : public testing::Test {};

TEST_F(UsersGroupsCacheTests, test_empty_cache) {
  GroupsCache groups_cache;

  EXPECT_TRUE(groups_cache.getAllGroups().empty());
  EXPECT_TRUE(groups_cache.getGroupsByGid(123).empty());
  EXPECT_FALSE(groups_cache.getGroupBySid("").has_value());

  UsersCache users_cache;
  EXPECT_TRUE(users_cache.getAllUsers().empty());
  EXPECT_TRUE(users_cache.getUsersByUid(123).empty());
  EXPECT_FALSE(users_cache.getUserBySid("").has_value());
}

TEST_F(UsersGroupsCacheTests, test_cache_initialization) {
  GroupsCache groups_cache;
  groups_cache.initializeCache(kDefaultGroups);

  EXPECT_THAT(kDefaultGroups,
              ::testing::ContainerEq(groups_cache.getAllGroups()));

  UsersCache users_cache;
  users_cache.initializeCache(kDefaultUsers);

  EXPECT_THAT(kDefaultUsers, ::testing::ContainerEq(users_cache.getAllUsers()));
}

TEST_F(UsersGroupsCacheTests, test_groups_cache_update) {
  GroupsCache groups_cache;
  Group group;
  group.groupname = "test";
  group.sid = "123";

  // Update the cache from an empty state
  groups_cache.updateGroup(group);

  auto groups = groups_cache.getAllGroups();
  ASSERT_EQ(groups.size(), 1);
  EXPECT_EQ(groups[0].groupname, "test");

  // Update the existing group information
  group.groupname = "test1";
  group.sid = "123";
  groups_cache.updateGroup(group);

  groups = groups_cache.getAllGroups();
  ASSERT_EQ(groups.size(), 1);
  EXPECT_EQ(groups[0].groupname, "test1");

  // Add a new group
  group.groupname = "test2";
  group.sid = "124";
  groups_cache.updateGroup(group);

  groups = groups_cache.getAllGroups();
  ASSERT_EQ(groups.size(), 2);
  EXPECT_EQ(groups[0].groupname, "test1");
  EXPECT_EQ(groups[1].groupname, "test2");
}

TEST_F(UsersGroupsCacheTests, test_users_cache_update) {
  UsersCache users_cache;
  User user;
  user.username = "test";
  user.sid = "123";

  // Update the cache from an empty state
  users_cache.updateUser(std::move(user));

  auto users = users_cache.getAllUsers();
  ASSERT_EQ(users.size(), 1);
  EXPECT_EQ(users[0].username, "test");

  // Update the existing user information
  user.username = "test1";
  user.sid = "123";
  users_cache.updateUser(user);

  users = users_cache.getAllUsers();
  ASSERT_EQ(users.size(), 1);
  EXPECT_EQ(users[0].username, "test1");

  // Add a new user
  user.username = "test2";
  user.sid = "124";
  users_cache.updateUser(user);

  users = users_cache.getAllUsers();
  ASSERT_EQ(users.size(), 2);
  EXPECT_EQ(users[0].username, "test1");
  EXPECT_EQ(users[1].username, "test2");
}

TEST_F(UsersGroupsCacheTests, test_groups_cache_search) {
  GroupsCache groups_cache;

  groups_cache.initializeCache(kDefaultGroups);
  auto groups = groups_cache.getGroupsByGid(457);

  ASSERT_EQ(groups.size(), 1);
  EXPECT_EQ(groups[0].gid, 457);
  EXPECT_EQ(groups[0].groupname, "test2");

  auto opt_group = groups_cache.getGroupBySid("S-123-457");
  ASSERT_TRUE(opt_group.has_value());
  const auto& group = *opt_group;

  EXPECT_EQ(group.gid, 457);
  EXPECT_EQ(group.groupname, "test2");

  /* Test that groups with different sids but same gid are all returned
     when searching via gid */
  Group new_group;
  new_group.sid = "S-124-457";
  new_group.gid = 457;
  new_group.groupname = "testdupgid";

  groups_cache.updateGroup(new_group);

  groups = groups_cache.getGroupsByGid(457);

  ASSERT_EQ(groups.size(), 2);
  EXPECT_EQ(groups[0].gid, 457);
  EXPECT_EQ(groups[0].groupname, "test2");
  EXPECT_EQ(groups[1], new_group);
}

TEST_F(UsersGroupsCacheTests, test_users_cache_search) {
  UsersCache users_cache;

  users_cache.initializeCache(kDefaultUsers);
  auto users = users_cache.getUsersByUid(457);

  ASSERT_EQ(users.size(), 1);
  EXPECT_EQ(users[0].uid, 457);
  EXPECT_EQ(users[0].username, "test2");

  auto opt_user = users_cache.getUserBySid("S-123-457");
  ASSERT_TRUE(opt_user.has_value());
  const auto& user = *opt_user;

  EXPECT_EQ(user.uid, 457);
  EXPECT_EQ(user.username, "test2");

  /* Test that users with different sids but same uid are all returned
     when searching via uid */
  User new_user;
  new_user.sid = "S-124-457";
  new_user.uid = 457;
  new_user.username = "testdupuid";

  users_cache.updateUser(new_user);

  users = users_cache.getUsersByUid(457);

  ASSERT_EQ(users.size(), 2);
  EXPECT_EQ(users[0].uid, 457);
  EXPECT_EQ(users[0].username, "test2");
  EXPECT_EQ(users[1], new_user);
}

TEST_F(UsersGroupsCacheTests, test_group_cache_cleaning) {
  GroupsCache groups_cache;
  groups_cache.cleanupExpiredGroups();

  groups_cache.initializeCache(kDefaultGroups);

  // "Confirm" that we have seen the last default group
  auto group = kDefaultGroups[2];
  groups_cache.updateGroup(group);
  groups_cache.increaseGeneration();
  groups_cache.cleanupExpiredGroups();

  auto groups = groups_cache.getAllGroups();
  ASSERT_EQ(groups.size(), 1);
  EXPECT_EQ(groups[0], group);

  // Test that it's still possible to search a group by gid or sid
  auto groups_by_gid = groups_cache.getGroupsByGid(458);
  ASSERT_EQ(groups_by_gid.size(), 1);
  EXPECT_EQ(groups_by_gid[0], group);

  auto group_by_sid = groups_cache.getGroupBySid("S-123-458");
  EXPECT_EQ(group_by_sid, group);

  groups_cache.increaseGeneration();
  groups_cache.cleanupExpiredGroups();
  EXPECT_TRUE(groups_cache.getAllGroups().empty());
}

TEST_F(UsersGroupsCacheTests, test_user_cache_cleaning) {
  UsersCache users_cache;
  users_cache.cleanupExpiredUsers();

  users_cache.initializeCache(kDefaultUsers);

  // "Confirm" that we have seen the last default user
  auto user = kDefaultUsers[2];
  users_cache.updateUser(user);
  users_cache.increaseGeneration();
  users_cache.cleanupExpiredUsers();

  auto users = users_cache.getAllUsers();
  ASSERT_EQ(users.size(), 1);
  EXPECT_EQ(users[0], user);

  // Test that it's still possible to search a user by uid or sid
  auto users_by_uid = users_cache.getUsersByUid(458);
  ASSERT_EQ(users_by_uid.size(), 1);
  EXPECT_EQ(users_by_uid[0], user);

  auto user_by_sid = users_cache.getUserBySid("S-123-458");
  EXPECT_EQ(user_by_sid, user);

  users_cache.increaseGeneration();
  users_cache.cleanupExpiredUsers();
  EXPECT_TRUE(users_cache.getAllUsers().empty());
}

} // namespace osquery

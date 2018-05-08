/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/packs.h>

#include "osquery/core/json.h"
#include "osquery/tests/test_util.h"

namespace osquery {

extern size_t getMachineShard(const std::string& hostname = "",
                              bool force = false);

class PacksTests : public testing::Test {};

TEST_F(PacksTests, test_parse) {
  auto doc = getExamplePacksConfig();
  EXPECT_TRUE(doc.doc().HasMember("packs"));
}

TEST_F(PacksTests, test_should_pack_execute) {
  Pack kpack("unrestricted_pack", getUnrestrictedPack().doc());
  EXPECT_TRUE(kpack.shouldPackExecute());

  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_FALSE(fpack.shouldPackExecute());
}

TEST_F(PacksTests, test_get_discovery_queries) {
  std::vector<std::string> expected;

  Pack kpack("unrestricted_pack", getUnrestrictedPack().doc());
  EXPECT_EQ(kpack.getDiscoveryQueries(), expected);

  expected = {"select pid from processes where name = 'foobar';"};
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_EQ(fpack.getDiscoveryQueries(), expected);
}

TEST_F(PacksTests, test_platform) {
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_EQ(fpack.getPlatform(), "all");
}

TEST_F(PacksTests, test_version) {
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_EQ(fpack.getVersion(), "1.5.0");
}

TEST_F(PacksTests, test_name) {
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  fpack.setName("also_discovery_pack");
  EXPECT_EQ(fpack.getName(), "also_discovery_pack");
}

TEST_F(PacksTests, test_sharding) {
  auto shard1 = getMachineShard("localhost.localdomain");
  auto shard2 = getMachineShard("not.localhost.localdomain");
  // Expect some static caching.
  EXPECT_EQ(shard1, shard2);

  // Bypass the caching.
  shard2 = getMachineShard("not.localhost.localdomain", true);
  EXPECT_NE(shard1, shard2);
}

TEST_F(PacksTests, test_check_platform) {
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_TRUE(fpack.checkPlatform());

  // Depending on the current build platform, this check will be true or false.
  fpack.platform_ = kSDKPlatform;
  EXPECT_TRUE(fpack.checkPlatform());

  fpack.platform_ = (kSDKPlatform == "darwin") ? "linux" : "darwin";
  EXPECT_FALSE(fpack.checkPlatform());

  fpack.platform_ = "null";
  EXPECT_TRUE(fpack.checkPlatform());

  fpack.platform_ = "";
  EXPECT_TRUE(fpack.checkPlatform());

  fpack.platform_ = "bad_value";
  EXPECT_FALSE(fpack.checkPlatform());

  fpack.platform_ = "posix";
  if (isPlatform(PlatformType::TYPE_POSIX) ||
      isPlatform(PlatformType::TYPE_LINUX) ||
      isPlatform(PlatformType::TYPE_OSX) ||
      isPlatform(PlatformType::TYPE_FREEBSD)) {
    EXPECT_TRUE(fpack.checkPlatform());
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_FALSE(fpack.checkPlatform());
  }
}

TEST_F(PacksTests, test_check_version) {
  Pack zpack("fake_version_pack", getPackWithFakeVersion().doc());
  EXPECT_FALSE(zpack.checkVersion());

  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_TRUE(fpack.checkVersion());
}

TEST_F(PacksTests, test_restriction_population) {
  // Require that all potential restrictions are populated before being checked.
  auto doc = getExamplePacksConfig();
  const auto& packs = doc.doc()["packs"];
  Pack fpack("fake_pack", packs["restricted_pack"]);

  ASSERT_FALSE(fpack.getPlatform().empty());
  ASSERT_FALSE(fpack.getVersion().empty());
  ASSERT_EQ(fpack.getShard(), 1U);
}

TEST_F(PacksTests, test_schedule) {
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  // Expect a single query in the schedule since one query has an explicit
  // invalid/fake platform requirement.
  EXPECT_EQ(fpack.getSchedule().size(), 1U);
}

TEST_F(PacksTests, test_discovery_cache) {
  Config c;
  // This pack and discovery query are valid, expect the SQL to execute.
  c.addPack("valid_discovery_pack", "", getPackWithValidDiscovery().doc());
  size_t query_count = 0U;
  size_t query_attemts = 5U;
  for (size_t i = 0; i < query_attemts; i++) {
    c.scheduledQueries(([&query_count](const std::string& name,
                                       std::shared_ptr<ScheduledQuery> query) {
      query_count++;
    }));
  }
  EXPECT_EQ(query_count, query_attemts);

  size_t pack_count = 0U;
  c.packs(([&pack_count, query_attemts](std::shared_ptr<Pack>& p) {
    pack_count++;
    // There is one pack without a discovery query.
    EXPECT_EQ(p->getStats().total, query_attemts + 1);
    EXPECT_EQ(p->getStats().hits, query_attemts);
    EXPECT_EQ(p->getStats().misses, 1U);
  }));

  EXPECT_EQ(pack_count, 1U);
  c.reset();
}

TEST_F(PacksTests, test_multi_pack) {
  std::string multi_pack_content = "{\"first\": {}, \"second\": {}}";
  auto multi_pack = JSON::newObject();
  multi_pack.fromString(multi_pack_content);

  Config c;
  c.addPack("*", "", multi_pack.doc());

  std::vector<std::string> pack_names;
  c.packs(([&pack_names](std::shared_ptr<Pack>& p) {
    pack_names.push_back(p->getName());
  }));

  std::vector<std::string> expected = {"first", "second"};
  ASSERT_EQ(expected.size(), pack_names.size());
  EXPECT_EQ(expected, pack_names);
}

TEST_F(PacksTests, test_discovery_zero_state) {
  Pack pack("discovery_pack", getPackWithDiscovery().doc());
  auto stats = pack.getStats();
  EXPECT_EQ(stats.total, 0U);
  EXPECT_EQ(stats.hits, 0U);
  EXPECT_EQ(stats.misses, 0U);
}

TEST_F(PacksTests, test_splay) {
  auto val1 = splayValue(100, 10);
  EXPECT_GE(val1, 90U);
  EXPECT_LE(val1, 110U);

  auto val2 = splayValue(100, 10);
  EXPECT_GE(val2, 90U);
  EXPECT_LE(val2, 110U);

  auto val3 = splayValue(10, 0);
  EXPECT_EQ(val3, 10U);

  auto val4 = splayValue(100, 1);
  EXPECT_GE(val4, 99U);
  EXPECT_LE(val4, 101U);

  auto val5 = splayValue(1, 10);
  EXPECT_EQ(val5, 1U);
}

TEST_F(PacksTests, test_restore_splay) {
  auto splay = restoreSplayedValue("pack_test_query_name", 3600);
  EXPECT_GE(splay, 3600U - 360);
  EXPECT_LE(splay, 3600U + 360);

  // If we restore, the splay should always be equal.
  for (size_t i = 0; i < 10; i++) {
    auto splay2 = restoreSplayedValue("pack_test_query_name", 3600);
    EXPECT_EQ(splay, splay2);
  }

  // If we modify the input interval the splay will change.
  auto splay3 = restoreSplayedValue("pack_test_query_name", 3600 * 10);
  EXPECT_GE(splay3, 3600U * 10 - (360 * 10));
  EXPECT_LE(splay3, 3600U * 10 + (360 * 10));
  EXPECT_NE(splay, splay3);
}
}

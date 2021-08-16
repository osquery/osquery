/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>

#include <osquery/config/tests/test_utils.h>

#include <osquery/config/packs.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>

#include <osquery/filesystem/filesystem.h>

#include <osquery/utils/info/platform_type.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>


namespace osquery {

extern size_t getMachineShard(const std::string& hostname = "",
                              bool force = false);

class PacksTests : public testing::Test {
 public:
  PacksTests() {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

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
  // First we exercise some basic functionality which should behave the same
  // regardless of the current build platform.
  Pack fpack("discovery_pack", getPackWithDiscovery().doc());
  EXPECT_TRUE(fpack.checkPlatform());

  fpack.platform_ = "null";
  EXPECT_TRUE(fpack.checkPlatform());

  fpack.platform_ = "";
  EXPECT_TRUE(fpack.checkPlatform());

  fpack.platform_ = "bad_value";
  EXPECT_FALSE(fpack.checkPlatform());

  // We should execute the query if the SDK platform is specified.
  fpack.platform_ = kSDKPlatform;
  EXPECT_TRUE(fpack.checkPlatform());
  // But not if something other than the SDK platform is speciifed.
  fpack.platform_ = (kSDKPlatform == "darwin") ? "linux" : "darwin";
  EXPECT_FALSE(fpack.checkPlatform());

  // For the remaining tests, we exercise all of the valid platform values.
  fpack.platform_ = "darwin";
  if (isPlatform(PlatformType::TYPE_OSX)) {
    EXPECT_TRUE(fpack.checkPlatform());
  } else {
    EXPECT_FALSE(fpack.checkPlatform());
  }

  fpack.platform_ = "freebsd";
  if (isPlatform(PlatformType::TYPE_FREEBSD)) {
    EXPECT_TRUE(fpack.checkPlatform());
  } else {
    EXPECT_FALSE(fpack.checkPlatform());
  }

  // Although officially no longer supported, we still treat the platform
  // values of "centos" and "ubuntu" just like "linux". We execute any query
  // with any of these platform values on any Linux system. For what it's
  // worth, we never actually differentiated between Linux distributions.
  for (auto p : std::set<std::string>{"centos", "linux", "ubuntu"}) {
    fpack.platform_ = p;
    if (isPlatform(PlatformType::TYPE_LINUX)) {
      EXPECT_TRUE(fpack.checkPlatform());
    } else {
      EXPECT_FALSE(fpack.checkPlatform());
    }
  }

  fpack.platform_ = "posix";
  if (isPlatform(PlatformType::TYPE_POSIX) ||
      isPlatform(PlatformType::TYPE_LINUX) ||
      isPlatform(PlatformType::TYPE_OSX) ||
      isPlatform(PlatformType::TYPE_FREEBSD)) {
    EXPECT_TRUE(fpack.checkPlatform());
  } else {
    EXPECT_FALSE(fpack.checkPlatform());
  }

  fpack.platform_ = "windows";
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_TRUE(fpack.checkPlatform());
  } else {
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
  size_t query_attempts = 5U;
  for (size_t i = 0; i < query_attempts; i++) {
    c.scheduledQueries(
        ([&query_count](std::string name, const ScheduledQuery& query) {
          query_count++;
        }));
  }
  EXPECT_EQ(query_count, query_attempts);

  size_t pack_count = 0U;
  c.packs(([&pack_count, query_attempts](const Pack& p) {
    pack_count++;
    // There is one pack without a discovery query.
    EXPECT_EQ(p.getStats().total, query_attempts + 1);
    EXPECT_EQ(p.getStats().hits, query_attempts);
    EXPECT_EQ(p.getStats().misses, 1U);
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
  c.packs(
      ([&pack_names](const Pack& p) { pack_names.push_back(p.getName()); }));

  std::vector<std::string> expected = {"first", "second"};
  ASSERT_EQ(expected.size(), pack_names.size());
  EXPECT_EQ(expected, pack_names);

  // We expect this to not throw an error.
  std::string bad_multi_pack_content = "{\"first\": \"\"}";
  auto bad_multi_pack = JSON::newObject();
  bad_multi_pack.fromString(bad_multi_pack_content);
  c.addPack("*", "", multi_pack.doc());
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

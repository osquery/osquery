/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/packs.h>

#include "osquery/core/test_util.h"

namespace osquery {

class PacksTests : public testing::Test {};

extern int splayValue(int original, int splayPercent);

pt::ptree getExamplePacksConfig() {
  std::string content;
  auto s = readFile(kTestDataPath + "test_inline_pack.conf", content);
  assert(s.ok());
  std::stringstream json;
  json << content;
  pt::ptree tree;
  pt::read_json(json, tree);
  return tree;
}

/// no discovery queries, no platform restriction
pt::ptree getUnrestrictedPack() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("kernel");
}

/// 1 discovery query, darwin platform restriction
pt::ptree getPackWithDiscovery() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("foobar");
}

/// 1 discovery query which will always pass
pt::ptree getPackWithValidDiscovery() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("baz");
}

/// no discovery queries, no platform restriction, fake version string
pt::ptree getPackWithFakeVersion() {
  auto tree = getExamplePacksConfig();
  auto packs = tree.get_child("packs");
  return packs.get_child("foobaz");
}

TEST_F(PacksTests, test_parse) {
  auto tree = getExamplePacksConfig();
  EXPECT_EQ(tree.count("packs"), 1);
}

TEST_F(PacksTests, test_should_pack_execute) {
  auto kpack = Pack("kernel", getUnrestrictedPack());
  EXPECT_TRUE(kpack.shouldPackExecute());

  auto fpack = Pack("foobar", getPackWithDiscovery());
  EXPECT_FALSE(fpack.shouldPackExecute());
}

TEST_F(PacksTests, test_get_discovery_queries) {
  std::vector<std::string> expected;

  auto kpack = Pack("kernel", getUnrestrictedPack());
  EXPECT_EQ(kpack.getDiscoveryQueries(), expected);

  expected = {"select pid from processes where name = 'foobar';"};
  auto fpack = Pack("foobar", getPackWithDiscovery());
  EXPECT_EQ(fpack.getDiscoveryQueries(), expected);
}

TEST_F(PacksTests, test_platform) {
  auto fpack = Pack("foobar", getPackWithDiscovery());
  EXPECT_EQ(fpack.getPlatform(), "darwin");
}

TEST_F(PacksTests, test_version) {
  auto fpack = Pack("foobar", getPackWithDiscovery());
  EXPECT_EQ(fpack.getVersion(), "1.5.0");
}

TEST_F(PacksTests, test_name) {
  auto fpack = Pack("foobar", getPackWithDiscovery());
  fpack.setName("foobar");
  EXPECT_EQ(fpack.getName(), "foobar");
}

TEST_F(PacksTests, test_check_platform) {
  auto fpack = Pack("foobar", getPackWithDiscovery());
  if (kSDKPlatform == "darwin") {
    EXPECT_TRUE(fpack.checkPlatform());
  } else {
    EXPECT_FALSE(fpack.checkPlatform());
  }
}

TEST_F(PacksTests, test_check_version) {
  auto fpack = Pack("foobar", getPackWithDiscovery());
  EXPECT_TRUE(fpack.checkVersion());

  auto zpack = Pack("foobaz", getPackWithFakeVersion());
  EXPECT_FALSE(zpack.checkVersion());
}

TEST_F(PacksTests, test_schedule) {
  auto fpack = Pack("foobar", getPackWithDiscovery());
  EXPECT_EQ(fpack.getSchedule().size(), 1);
}

TEST_F(PacksTests, test_discovery_cache) {
  auto pack = Pack("kernel", getPackWithValidDiscovery());
  auto& stats = pack.getStats();
  EXPECT_EQ(stats.total, 0);
  EXPECT_EQ(stats.hits, 0);
  EXPECT_EQ(stats.misses, 0);

  auto c = Config();
  c.addPack(pack);
  int query_count = 0;
  for (int i = 0; i < 5; i++) {
    c.scheduledQueries(
        ([&query_count](const std::string& name, const ScheduledQuery& query) {
          query_count++;
         }));
  }
  EXPECT_EQ(query_count, 5);

  int pack_count = 0;
  c.packs(([&pack_count](Pack& p) {
    pack_count++;
    EXPECT_EQ(p.getStats().total, 5);
    EXPECT_EQ(p.getStats().hits, 4);
    EXPECT_EQ(p.getStats().misses, 1);
  }));

  EXPECT_EQ(pack_count, 1);
}

TEST_F(PacksTests, test_discovery_zero_state) {
  auto pack = Pack("foobar", getPackWithDiscovery());
  auto stats = pack.getStats();
  EXPECT_EQ(stats.total, 0);
  EXPECT_EQ(stats.hits, 0);
  EXPECT_EQ(stats.misses, 0);
}

TEST_F(PacksTests, test_splay) {
  auto val1 = splayValue(100, 10);
  EXPECT_GE(val1, 90);
  EXPECT_LE(val1, 110);

  auto val2 = splayValue(100, 10);
  EXPECT_GE(val2, 90);
  EXPECT_LE(val2, 110);

  auto val3 = splayValue(10, 0);
  EXPECT_EQ(val3, 10);

  auto val4 = splayValue(100, 1);
  EXPECT_GE(val4, 99);
  EXPECT_LE(val4, 101);

  auto val5 = splayValue(1, 10);
  EXPECT_EQ(val5, 1);
}
}

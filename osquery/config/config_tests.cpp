/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <fstream>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include <boost/filesystem/operations.hpp>

#include "osquery/core/test_util.h"

namespace osquery {

// The config_path flag is defined in the filesystem config plugin.
DECLARE_string(config_path);
const std::string kFakeDirectory = "/tmp/osquery-fstests-pattern";

class ConfigTests : public testing::Test {
 public:
  ConfigTests() {
    FLAGS_config_plugin = "filesystem";
    FLAGS_config_path = kTestDataPath + "test.config";
  }

 protected:
  void createFileAt(const std::string loc, const std::string content) {
    std::ofstream test_file(loc);
    test_file.write(content.c_str(), sizeof("test123"));
    test_file.close();
  }

  void SetUp() {
    boost::filesystem::create_directories(kFakeDirectory +
                                          "/deep11/deep2/deep3/");
    boost::filesystem::create_directories(kFakeDirectory + "/deep1/deep2/");

    createFileAt(kFakeDirectory + "/root.txt", "root");
    createFileAt(kFakeDirectory + "/toor.txt", "toor");
    createFileAt(kFakeDirectory + "/roto.txt", "roto");
    createFileAt(kFakeDirectory + "/deep1/level1.txt", "l1");
    createFileAt(kFakeDirectory + "/deep11/not_bash", "l1");
    createFileAt(kFakeDirectory + "/deep1/deep2/level2.txt", "l2");

    createFileAt(kFakeDirectory + "/deep11/level1.txt", "l1");
    createFileAt(kFakeDirectory + "/deep11/deep2/level2.txt", "l2");
    createFileAt(kFakeDirectory + "/deep11/deep2/deep3/level3.txt", "l3");

    Registry::setUp();
    auto c = Config::getInstance();
    c->load();
  }

  void TearDown() { boost::filesystem::remove_all(kFakeDirectory); }
};

class TestConfigPlugin : public ConfigPlugin {
 public:
  TestConfigPlugin() {}

  std::pair<Status, std::string> genConfig() {
    return std::make_pair(Status(0, "OK"), "foobar");
  }
};

TEST_F(ConfigTests, test_plugin) {
  Registry::add<TestConfigPlugin>("config", "test");

  PluginResponse response;
  auto status =
      Registry::call("config", "test", {{"action", "genConfig"}}, response);

  EXPECT_EQ(status.ok(), true);
  EXPECT_EQ(status.toString(), "OK");
  EXPECT_EQ(response[0].at("data"), "foobar");
}

TEST_F(ConfigTests, test_queries_execute) {
  auto c = Config::getInstance();
  auto queries = c->getScheduledQueries();

  EXPECT_EQ(queries.size(), 1);
  for (const auto& i : queries) {
    QueryData results;
    auto status = query(i.query, results);
    EXPECT_TRUE(status.ok());
  }
}

TEST_F(ConfigTests, test_threatfiles_execute) {
  auto c = Config::getInstance();
  // files_f is of type std::shared_pointer
  auto files_f = c->getThreatFiles();
  auto files = files_f.get();

  EXPECT_EQ(files.size(), 2);
  EXPECT_EQ(files["downloads"].size(), 9);
  EXPECT_EQ(files["system_binaries"].size(), 5);
  // Do this twice to test the fact that multiple calls work
  // with futures;
  files_f = c->getThreatFiles();
  files = files_f.get();

  EXPECT_EQ(files.size(), 2);
  EXPECT_EQ(files["downloads"].size(), 9);
  EXPECT_EQ(files["system_binaries"].size(), 5);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

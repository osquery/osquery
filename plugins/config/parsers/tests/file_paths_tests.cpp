/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/utils/conversions/tryto.h>

#include <set>

namespace osquery {

class FilePathsConfigParserPluginTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    // Read config content manually.
    readFile(getTestConfigDirectory() / "test_parse_items.conf", content_);

    // Construct a config map, the typical output from `Config::genConfig`.
    config_data_["awesome"] = content_;
    Config::get().reset();
  }

  void TearDown() override {
    Config::get().reset();
  }

  size_t numFiles() {
    size_t count = 0;
    Config::get().files(([&count](
        const std::string&, const std::vector<std::string>&) { count++; }));
    return count;
  }

 protected:
  std::string content_;
  std::map<std::string, std::string> config_data_;
};

TEST_F(FilePathsConfigParserPluginTests, test_get_files) {
  std::set<std::string> expected_categories = {"config_files", "logs", "logs"};
  std::set<std::string> expected_values = {
      "/dev", "/dev/zero", "/dev/null", "/dev/random"};

  // This tests the file_paths_query feature.
  expected_categories.insert("config_files_query");
  expected_values.insert("/dev/urandom");

  std::set<std::string> categories;
  std::set<std::string> values;
  Config::get().update(config_data_);
  Config::get().files(
      ([&categories, &values](const std::string& category,
                              const std::vector<std::string>& files) {
        categories.insert(category);
        for (const auto& file : files) {
          values.insert(file);
        }
      }));

  EXPECT_EQ(categories, expected_categories);
  EXPECT_EQ(values, expected_values);
}

TEST_F(FilePathsConfigParserPluginTests, test_get_file_accesses) {
  Config::get().update(config_data_);
  auto parser = Config::getParser("file_paths");
  const auto& doc = parser->getData();

  ASSERT_TRUE(doc.doc().HasMember("file_accesses"));
  ASSERT_TRUE(doc.doc()["file_accesses"].IsArray());
  EXPECT_EQ(doc.doc()["file_accesses"].Size(), 2_sz);
}

TEST_F(FilePathsConfigParserPluginTests, test_get_exclude_paths) {
  Config::get().update(config_data_);
  auto parser = Config::getParser("file_paths");
  const auto& doc = parser->getData();

  ASSERT_TRUE(doc.doc().HasMember("exclude_paths"));
  ASSERT_TRUE(doc.doc()["exclude_paths"].IsObject());
  ASSERT_TRUE(doc.doc()["exclude_paths"].HasMember("example"));
  ASSERT_TRUE(doc.doc()["exclude_paths"]["example"].IsArray());
  EXPECT_EQ(doc.doc()["exclude_paths"]["example"].Size(), 1_sz);
}

TEST_F(FilePathsConfigParserPluginTests, test_remove_source) {
  Config::get().update(config_data_);
  Config::get().removeFiles("awesome");
  // Expect the pack's set to persist.
  // Do not call removeFiles, instead only update the pack/config content.
  EXPECT_EQ(numFiles(), 1U);

  // This will clear all source data for 'awesome'.
  config_data_["awesome"] = "";
  Config::get().update(config_data_);
  EXPECT_EQ(numFiles(), 0U);
}

namespace {

/// A parser config whose file_paths_query update() defers to afterUpdate().
ConfigParserPlugin::ParserConfig filePathsQueryConfig() {
  ConfigParserPlugin::ParserConfig config;
  auto file_paths_query = JSON::newObject();
  auto queries = file_paths_query.getArray();
  file_paths_query.pushCopy("select '/dev/urandom' as path", queries);
  file_paths_query.addCopy("config_files_query", queries);
  config.emplace("file_paths_query", std::move(file_paths_query));
  return config;
}

} // namespace

TEST_F(FilePathsConfigParserPluginTests, test_pending_query_added) {
  auto parser = Config::getParser("file_paths");
  ASSERT_NE(parser, nullptr);

  ASSERT_TRUE(parser->update("awesome", filePathsQueryConfig()).ok());
  parser->afterUpdate();

  // Without an intervening removal, the deferred query's paths are added.
  EXPECT_EQ(numFiles(), 1U);
}
}

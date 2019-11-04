/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/config/config.h>
#include <osquery/config/config_parser_plugin.h>
#include <osquery/config/config_plugin.h>
#include <osquery/config/config_refresh.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>
#include <osquery/utils/system/time.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace osquery {

DECLARE_uint64(config_refresh);
DECLARE_uint64(config_accelerated_refresh);
DECLARE_bool(config_enable_backup);
DECLARE_bool(disable_database);

class ConfigRefreshTests : public testing::Test {
 public:
  ConfigRefreshTests() {
    platformSetup();
    registryAndPluginInit();
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();

    Config::get().reset();
  }

 protected:
  void SetUp() {
    refresh_ = FLAGS_config_refresh;
    FLAGS_config_refresh = 0;
  }

  void TearDown() {
    FLAGS_config_refresh = refresh_;
  }

 protected:
  Config& get() {
    return Config::get();
  }

 private:
  size_t refresh_{0};
};

class RefreshConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(ConfigMap& config) override {
    gen_config_count_++;
    if (fail_) {
      return Status::failure("Requested fail");
    }
    return Status::success();
  }

  Status genPack(const std::string& name,
                 const std::string& value,
                 std::string& pack) override {
    gen_pack_count_++;
    return Status::success();
  }

 public:
  std::atomic<bool> fail_{false};
  std::atomic<size_t> gen_config_count_{0};
  std::atomic<size_t> gen_pack_count_{0};
};

TEST_F(ConfigRefreshTests, test_pack_noninline) {
  auto& rf = RegistryFactory::get();
  rf.registry("config")->add("test", std::make_shared<RefreshConfigPlugin>());
  // Change the active config plugin.
  EXPECT_TRUE(rf.setActive("config", "test").ok());

  // Get a specialized config/test plugin.
  const auto& plugin = std::dynamic_pointer_cast<RefreshConfigPlugin>(
      rf.plugin("config", "test"));

  auto runner = std::make_shared<ConfigRefreshRunner>();
  runner->refresh();

  // Expect the test plugin to have recorded 1 pack.
  // This value is incremented when its genPack method is called.
  EXPECT_EQ(plugin->gen_pack_count_, 1U);

  int total_packs = 0;
  // Expect the config to have recorded a pack for the inline and non-inline.
  get().packs([&total_packs](const Pack& pack) { total_packs++; });
  EXPECT_EQ(total_packs, 2);
  rf.registry("config")->remove("test");
}

TEST_F(ConfigRefreshTests, test_config_refresh) {
  auto& rf = RegistryFactory::get();
  auto refresh = FLAGS_config_refresh;
  auto refresh_acceleratred = FLAGS_config_accelerated_refresh;

  // Create and add a test plugin.
  auto plugin = std::make_shared<RefreshConfigPlugin>();
  EXPECT_TRUE(rf.registry("config")->add("test", plugin));
  EXPECT_TRUE(rf.setActive("config", "test"));

  // Reset the configuration and stop the refresh thread.
  get().reset();

  auto runner = std::make_shared<ConfigRefreshRunner>();
  runner->refresh();

  // Set a config_refresh value to convince the Config to start the thread.
  FLAGS_config_refresh = 2;
  FLAGS_config_accelerated_refresh = 1;
  runner->setRefresh(FLAGS_config_refresh);

  // Fail the first config load.
  plugin->fail_ = true;

  // The runner will wait at least one refresh-delay.
  auto count = static_cast<size_t>(plugin->gen_config_count_);

  runner->refresh();
  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(runner->getRefresh(), FLAGS_config_accelerated_refresh);

  plugin->fail_ = false;
  count = static_cast<size_t>(plugin->gen_config_count_);

  runner->refresh();
  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(runner->getRefresh(), FLAGS_config_refresh);

  // Now make the configuration break.
  plugin->fail_ = true;
  count = static_cast<size_t>(plugin->gen_config_count_);

  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(runner->getRefresh(), FLAGS_config_accelerated_refresh);

  // Test that the normal acceleration is restored.
  plugin->fail_ = false;
  count = static_cast<size_t>(plugin->gen_config_count_);

  EXPECT_GT(plugin->gen_config_count_, count);
  EXPECT_EQ(runner->getRefresh(), FLAGS_config_refresh);

  FLAGS_config_refresh = refresh;
  FLAGS_config_accelerated_refresh = refresh_acceleratred;
  rf.registry("config")->remove("test");
}

class TestDataConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"data"};
  }

  Status setUp() override {
    return Status::success();
  }

  Status update(const std::string& source,
                const ParserConfig& config) override {
    source_ = source;
    config_.clear();
    for (const auto& entry : config) {
      std::string content;
      entry.second.toString(content);
      config_[entry.first] = content;
    }
    return Status::success();
  }

  std::string source_{""};
  ConfigMap config_;
};

TEST_F(ConfigRefreshTests, test_config_backup_integrate) {
  const auto config_enable_backup_saved = FLAGS_config_enable_backup;
  FLAGS_config_enable_backup = true;

  get().reset();
  auto& rf = RegistryFactory::get();
  auto data_parser = std::make_shared<TestDataConfigParserPlugin>();
  auto success_plugin = std::make_shared<RefreshConfigPlugin>();
  success_plugin->fail_ = false;

  auto fail_plugin = std::make_shared<RefreshConfigPlugin>();
  fail_plugin->fail_ = true;

  rf.registry("config")->add("test_success", success_plugin);
  rf.registry("config")->add("test_fail", fail_plugin);
  rf.registry("config_parser")->add("test", data_parser);
  // Change the active config plugin.
  EXPECT_TRUE(rf.setActive("config", "test_success").ok());

  auto runner = std::make_shared<ConfigRefreshRunner>();
  auto status = runner->refresh();

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(success_plugin->gen_config_count_, 1);

  auto source_backup = data_parser->source_;
  auto config_backup = data_parser->config_;

  EXPECT_TRUE(source_backup.length() > 0);

  get().reset();
  data_parser->source_.clear();
  data_parser->config_.clear();
  EXPECT_TRUE(rf.setActive("config", "test_fail").ok());

  runner->refresh();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(fail_plugin->gen_config_count_, 1);

  EXPECT_EQ(data_parser->source_, source_backup);
  EXPECT_EQ(data_parser->config_, config_backup);

  FLAGS_config_enable_backup = config_enable_backup_saved;
}
} // namespace osquery

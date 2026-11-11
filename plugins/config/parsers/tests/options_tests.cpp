/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/extensions/interface.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/scope_guard.h>

namespace osquery {

FLAG(bool, test_options_race_parser, false, "");

class OptionsConfigParserPluginTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

class TestOptionsRaceParser : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"before_options"};
  }

  Status setUp() override {
    return Status::success();
  }

  Status update(const std::string&, const ParserConfig&) override {
    if (!FLAGS_test_options_race_parser) {
      throw std::runtime_error("The flag test_options_race_parser is false");
    }
    return Status::success();
  }
};

TEST_F(OptionsConfigParserPluginTests, test_get_option) {
  Config c;
  auto s = c.update(getTestConfigMap("test_parse_items.conf"));
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  const auto& parser = c.getParser("options")->getData();
  ASSERT_FALSE(parser.doc().HasMember("options"));

  c.reset();
}

TEST_F(OptionsConfigParserPluginTests, test_get_option_first) {
  auto& rf = RegistryFactory::get();
  auto options_race_parser = std::make_shared<TestOptionsRaceParser>();
  rf.registry("config_parser")->add("before_options", options_race_parser);

  Config c;
  std::map<std::string, std::string> update;
  update["options"] = "{\"options\": {\"test_options_race_parser\": true}}";
  EXPECT_NO_THROW(c.update(update));

  rf.registry("config_parser")->remove("before_options");
  c.reset();
}

TEST_F(OptionsConfigParserPluginTests, test_unknown_option) {
  Config c;
  std::map<std::string, std::string> update;

  update["awesome"] =
      "{\"options\": {\"fake\": 1, \"custom_fake\": 1, \"fake_custom_fake\": "
      "1}}";
  auto s = c.update(update);

  // This looks funky, because the parser is named 'options' and it claims
  // ownership of a single top-level-key called 'options'.
  const auto& doc = c.getParser("options")->getData().doc()["options"];

  // Since 'fake' was not defined as a flag, it is not an option.
  EXPECT_TRUE(doc.HasMember("fake"));
  EXPECT_TRUE(Flag::getValue("fake").empty());

  // The word 'custom_' must be a prefix.
  EXPECT_TRUE(doc.HasMember("fake_custom_fake"));
  EXPECT_TRUE(Flag::getValue("fake_custom_fake").empty());

  // This should work.
  ASSERT_TRUE(doc.HasMember("custom_fake"));
  EXPECT_TRUE(doc["custom_fake"].IsNumber());
  EXPECT_EQ(1U, doc["custom_fake"].GetUint());
  EXPECT_FALSE(Flag::getValue("custom_fake").empty());
}

TEST_F(OptionsConfigParserPluginTests, test_json_option) {
  Config c;
  std::map<std::string, std::string> update;

  update["awesome"] = R"raw({
    "options": {
      "custom_nested_json":
        {"foo":1,"bar":"baz"}
    }
  })raw";
  auto s = c.update(update);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  const auto& doc = c.getParser("options")->getData().doc()["options"];

  EXPECT_TRUE(doc.HasMember("custom_nested_json"));
  EXPECT_FALSE(Flag::getValue("custom_nested_json").empty());
  EXPECT_EQ(R"raw({"foo":1,"bar":"baz"})raw",
            Flag::getValue("custom_nested_json"));
}

TEST_F(OptionsConfigParserPluginTests,
       test_concurrent_custom_option_update_and_extension_snapshot) {
  const std::string name{"custom_options_snapshot_test"};
  const std::string inserted_prefix{name + "_inserted_"};
  const std::string first_value(256, 'a');
  const std::string second_value(1024, 'b');
  constexpr std::size_t kIterations = 500;
  constexpr std::size_t kInsertedKeys = 16;

  std::mutex start_mutex;
  std::condition_variable start_condition;
  std::size_t ready{0U};
  bool start{false};

  auto waitForStart = [&]() {
    std::unique_lock<std::mutex> lock(start_mutex);
    ++ready;
    start_condition.notify_all();
    start_condition.wait(lock, [&]() { return start; });
  };

  std::atomic<bool> values_valid{true};
  auto checkValue = [&](const std::string& value) {
    if (value != first_value && value != second_value) {
      values_valid.store(false, std::memory_order_relaxed);
    }
  };

  std::map<std::string, std::string> saved_custom_flags;
  for (const auto& flag : Flag::flags()) {
    if (flag.first.find("custom_") == 0U && Flag::getType(flag.first).empty()) {
      saved_custom_flags.emplace(flag.first, flag.second.value);
    }
  }
  Flag::resetCustomFlags();

  Config config;
  config.reset();
  const auto state_guard = scope_guard::create([&]() {
    config.reset();
    Flag::resetCustomFlags();
    for (const auto& flag : saved_custom_flags) {
      Flag::updateValue(flag.first, flag.second);
    }
  });

  std::thread config_writer([&]() {
    waitForStart();
    for (std::size_t i = 0; i < kIterations; ++i) {
      const auto& value = i % 2U == 0U ? first_value : second_value;
      const auto inserted_name =
          inserted_prefix + std::to_string(i % kInsertedKeys);
      std::map<std::string, std::string> update;
      update["custom_options_test"] = "{\"options\":{\"" + name + "\":\"" +
                                      value + "\",\"" + inserted_name +
                                      "\":\"" + value + "\"}}";

      if (!config.update(update).ok()) {
        values_valid.store(false, std::memory_order_relaxed);
      }
    }
  });

  std::thread extension_reader([&]() {
    waitForStart();
    ExtensionManagerInterface extension_manager;
    for (std::size_t i = 0; i < kIterations; ++i) {
      const auto options = extension_manager.options();
      const auto value = options.find(name);
      if (value != options.end()) {
        checkValue(value->second.value);
      }
      for (const auto& option : options) {
        if (option.first.find(inserted_prefix) == 0U) {
          checkValue(option.second.value);
        }
      }
    }
  });

  {
    std::unique_lock<std::mutex> lock(start_mutex);
    start_condition.wait(lock, [&]() { return ready == 2U; });
    start = true;
  }
  start_condition.notify_all();

  config_writer.join();
  extension_reader.join();

  EXPECT_TRUE(values_valid.load(std::memory_order_relaxed));
  const auto options = ExtensionManagerInterface().options();
  ASSERT_EQ(options.count(name), 1U);
  EXPECT_EQ(options.at(name).value, second_value);
  for (std::size_t i = 0; i < kInsertedKeys; ++i) {
    const auto inserted_name = inserted_prefix + std::to_string(i);
    ASSERT_EQ(options.count(inserted_name), 1U);
    const auto& expected_value = i % 2U == 0U ? first_value : second_value;
    EXPECT_EQ(options.at(inserted_name).value, expected_value);
  }
  EXPECT_TRUE(values_valid.load(std::memory_order_relaxed));
}
} // namespace osquery

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/config/tests/test_utils.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>

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
}

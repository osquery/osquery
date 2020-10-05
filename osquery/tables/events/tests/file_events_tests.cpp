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
#include <osquery/events/events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/event_utils.h>

namespace osquery {

DECLARE_bool(registry_exceptions);

class FileEventSubscriber;

class FileEventsTableTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    Config::get().reset();

    // Promote registry access exceptions when testing tables and SQL.
    exceptions_ = FLAGS_registry_exceptions;
    FLAGS_registry_exceptions = true;

    // Setup configuration parsers for file paths accesses.
    Registry::get().registry("config_parser")->setUp();
  }

  void TearDown() override {
    FLAGS_registry_exceptions = exceptions_;
  }

 protected:
  Status load() {
    return Config::get().load();
  }

 private:
  bool exceptions_{false};
};

#ifndef WIN32
TEST_F(FileEventsTableTests, test_subscriber_exists) {
  ASSERT_TRUE(Registry::get().exists("event_subscriber", "file_events"));

  // Note: do not perform a reinterpret cast like this.
  auto plugin = Registry::get().plugin("event_subscriber", "file_events");
  auto* subscriber =
      reinterpret_cast<std::shared_ptr<FileEventSubscriber>*>(&plugin);
  EXPECT_NE(subscriber, nullptr);
}
#endif

TEST_F(FileEventsTableTests, test_table_empty) {
  // Attach/create the publishers.
  attachEvents();

  auto results = SQL::selectAllFrom("file_events");
  EXPECT_EQ(results.size(), 0U);
}

class FileEventsTestsConfigPlugin : public ConfigPlugin {
 public:
  Status genConfig(std::map<std::string, std::string>& config) override {
    auto doc = getUnrestrictedPack();
    return doc.toString(config["data"]);
  }
};

#ifndef WIN32
TEST_F(FileEventsTableTests, test_configure_subscriptions) {
  // Attach/create the publishers.
  attachEvents();

  // Load a configuration with file paths, verify subscriptions.
  auto registry = RegistryFactory::get().registry("config");
  registry->add("file_events_tests",
                std::make_shared<FileEventsTestsConfigPlugin>());
  RegistryFactory::get().setActive("config", "file_events_tests");
  this->load();

  // Explicitly request a configure for subscribers.
  Registry::get().registry("event_subscriber")->configure();

  std::string q = "select * from osquery_events where name = 'file_events'";

  {
    SQL results(q);
    ASSERT_EQ(results.rows().size(), 1U);
    auto& row = results.rows()[0];
    // Expect the paths within "unrestricted_pack" to be created as
    // subscriptions.
    EXPECT_EQ(row.at("subscriptions"), "2");
  }

  // The most important part, make sure a reconfigure removes the subscriptions.
  Config::get().update({{"data", "{}"}});

  {
    SQL results(q);
    auto& row2 = results.rows()[0];
    EXPECT_EQ(row2.at("subscriptions"), "0");
  }
}
#endif /* WIN32 */
} // namespace osquery

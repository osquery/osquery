/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <plugins/logger/filesystem_logger.h>

#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/logger/data_logger.h>
#include <osquery/registry/registry_factory.h>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(logger_path);
DECLARE_bool(disable_logging);
DECLARE_bool(logger_numerics);

class FilesystemLoggerTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    auto logger_path =
        fs::temp_directory_path() /
        fs::unique_path("osquery.filesystem_logger_tests.%%%%.%%%%.logs");

    FLAGS_logger_path = logger_path.string();
    fs::create_directories(FLAGS_logger_path);

    // Set the expected results path.
    results_path_ = (logger_path / "osqueryd.results.log").string();

    FLAGS_disable_logging = false;

    EXPECT_TRUE(Registry::get().exists("logger", "filesystem"));

    // This will attempt to log a string (an empty string).
    EXPECT_TRUE(Registry::get().setActive("logger", "filesystem"));
    EXPECT_TRUE(Registry::get().plugin("logger", "filesystem")->setUp());

    ASSERT_TRUE(fs::exists(results_path_));

    // Make sure the content is empty.
    std::string content;
    EXPECT_TRUE(readFile(results_path_, content));
    EXPECT_EQ(content, "");
  }

  void TearDown() override {}

  std::string getContent() {
    return std::string();
  }

  /// Results log path.
  std::string results_path_;
};

TEST_F(FilesystemLoggerTests, test_log_string) {
  EXPECT_TRUE(logString("{\"json\": true}", "event"));

  std::string content;
  EXPECT_TRUE(readFile(results_path_, content));
  EXPECT_EQ(content, "{\"json\": true}\n");
}

class FilesystemTestLoggerPlugin : public LoggerPlugin {
 public:
  Status logString(const std::string& s) override {
    return Status(0);
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    return Status(0, "OK");
  }

  bool usesLogStatus() override {
    return true;
  }

 protected:
  void init(const std::string& binary_name,
            const std::vector<StatusLogLine>& log) override {}
};

TEST_F(FilesystemLoggerTests, test_log_status) {
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    // Cannot test status deterministically on windows.
    return;
  }

  initStatusLogger("osqueryd");
  initLogger("osqueryd");

  LOG(WARNING) << "Filesystem logger test is generating a warning status (1/3)";

  auto status_path = fs::path(FLAGS_logger_path) / "osqueryd.INFO";
  EXPECT_TRUE(osquery::pathExists(status_path));

  std::string content;
  EXPECT_TRUE(readFile(status_path, content));
  auto lines = osquery::split(content, "\n").size();
  EXPECT_EQ(5U, lines);

  LOG(WARNING) << "Filesystem logger test is generating a warning status (2/3)";
  content.clear();
  readFile(status_path, content);
  lines = osquery::split(content, "\n").size();
  EXPECT_EQ(6U, lines);

  auto& rf = RegistryFactory::get();
  auto filesystem_test = std::make_shared<FilesystemTestLoggerPlugin>();
  rf.registry("logger")->add("filesystem_test", filesystem_test);
  EXPECT_TRUE(rf.setActive("logger", "filesystem,filesystem_test").ok());

  LOG(WARNING) << "Filesystem logger test is generating a warning status (3/3)";
  content.clear();
  readFile(status_path, content);
  lines = osquery::split(content, "\n").size();
  EXPECT_EQ(7U, lines);

  relayStatusLogs(LoggerRelayMode::Async);
  content.clear();
  readFile(status_path, content);
  lines = osquery::split(content, "\n").size();
  EXPECT_EQ(7U, lines);
}

TEST_F(FilesystemLoggerTests, test_log_snapshot) {
  QueryLogItem item;
  item.name = "test";
  item.identifier = "test";
  item.time = 0;
  item.calendar_time = "test";
  item.epoch = 0L;
  item.counter = 0L;

  EXPECT_TRUE(logSnapshotQuery(item));
  auto snapshot_path = fs::path(FLAGS_logger_path) / "osqueryd.snapshots.log";
  ASSERT_TRUE(fs::exists(snapshot_path));

  // Write a second snapshot item, and make sure there is a newline between
  // the two log lines.
  EXPECT_TRUE(logSnapshotQuery(item));
  std::string content;
  EXPECT_TRUE(readFile(snapshot_path.string(), content));

  std::string expected =
      "{\"snapshot\":[],\"action\":\"snapshot\",\"name\":\"test\","
      "\"hostIdentifier\":\"test\",\"calendarTime\":\"test\","
      "\"unixTime\":0,\"epoch\":0,\"counter\":0,\"numerics\":" +
      std::string(FLAGS_logger_numerics ? "true" : "false") +
      "}\n{\"snapshot\":[],\"action\":\"snapshot\","
      "\"name\":\"test\",\"hostIdentifier\":\"test\",\"calendarTime\":\"test\","
      "\"unixTime\":0,\"epoch\":0,\"counter\":0,\"numerics\":" +
      std::string(FLAGS_logger_numerics ? "true" : "false") + "}\n";
  EXPECT_EQ(content, expected);
}
} // namespace osquery

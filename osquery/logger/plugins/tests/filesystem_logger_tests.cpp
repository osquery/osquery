/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>

#include <osquery/logger.h>

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(logger_path);

class FilesystemLoggerTests : public testing::Test {
 public:
  void SetUp() override {
    auto logger_path = fs::path(kTestWorkingDirectory) / "unittests.logs";
    FLAGS_logger_path = logger_path.string();
    fs::create_directories(FLAGS_logger_path);

    // Set the expected results path.
    results_path_ = (logger_path / "osqueryd.results.log").string();

    // Backup the logging status, then disable.
    logging_status_ = FLAGS_disable_logging;
    FLAGS_disable_logging = false;
  }

  void TearDown() override {
    FLAGS_disable_logging = logging_status_;
  }

  std::string getContent() {
    return std::string();
  }

 protected:
  /// Save the status of logging before running tests, restore afterward.
  bool logging_status_{true};

  /// Results log path.
  std::string results_path_;
};

TEST_F(FilesystemLoggerTests, test_filesystem_init) {
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

TEST_F(FilesystemLoggerTests, test_log_string) {
  EXPECT_TRUE(logString("{\"json\": true}", "event"));

  std::string content;
  EXPECT_TRUE(readFile(results_path_, content));
  EXPECT_EQ(content, "{\"json\": true}\n");
}

TEST_F(FilesystemLoggerTests, test_log_snapshot) {
  QueryLogItem item;
  item.name = "test";
  item.identifier = "test";
  item.time = 0;
  item.calendar_time = "test";

  EXPECT_TRUE(logSnapshotQuery(item));
  auto snapshot_path = fs::path(FLAGS_logger_path) / "osqueryd.snapshots.log";
  ASSERT_TRUE(fs::exists(snapshot_path));

  // Write a second snapshot item, and make sure there is a newline between
  // the two log lines.
  EXPECT_TRUE(logSnapshotQuery(item));
  std::string content;
  EXPECT_TRUE(readFile(snapshot_path.string(), content));

  std::string expected =
      "{\"snapshot\":\"\",\"action\":\"snapshot\",\"name\":\"test\","
      "\"hostIdentifier\":\"test\","
      "\"calendarTime\":\"test\",\"unixTime\":\"0\"}\n{\"snapshot\":\"\","
      "\"action\":\"snapshot\","
      "\"name\":\"test\",\"hostIdentifier\":\"test\",\"calendarTime\":\"test\","
      "\"unixTime\":\"0\"}\n";
  EXPECT_EQ(content, expected);
}
}

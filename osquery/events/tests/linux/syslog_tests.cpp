/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/syslog.h>
#include <osquery/tests/test_util.h>

#include <boost/filesystem.hpp>
#include <boost/tokenizer.hpp>

#include <gtest/gtest.h>

#include <vector>

namespace fs = boost::filesystem;

namespace osquery {

class SyslogTests : public testing::Test {
 public:
  void SetUp() override {
    test_working_dir_ = fs::temp_directory_path() /
                        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);
  }

  void TearDown() override {
    fs::remove_all(test_working_dir_);
  }

  std::vector<std::string> splitCsv(std::string line) {
    boost::tokenizer<RsyslogCsvSeparator> tokenizer(line);
    std::vector<std::string> result(tokenizer.begin(), tokenizer.end());
    return result;
  }

 protected:
  fs::path test_working_dir_;
};

TEST_F(SyslogTests, test_nonblockingfstream) {
  auto pipe_path = test_working_dir_ / "pipe";
  auto ret = mkfifo(pipe_path.string().c_str(), 0660);
  ASSERT_EQ(ret, 0);
  ret = chmod(pipe_path.string().c_str(), 0660);
  ASSERT_EQ(ret, 0);

  NonBlockingFStream nbfs(20);
  auto s = nbfs.openReadOnly(pipe_path.string());
  EXPECT_TRUE(s.ok());

  auto fd = open(pipe_path.string().c_str(), O_WRONLY | O_NONBLOCK);
  ASSERT_GT(fd, 0);

  std::string fill(19, 'A');
  fill.push_back('\n');
  auto bytes_written = write(fd, fill.data(), fill.size());
  ASSERT_EQ(20, bytes_written);

  std::string output;
  s = nbfs.getline(output);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(0, nbfs.offset());

  {
    std::string expected;
    std::copy(fill.begin(), fill.end() - 1, std::back_inserter(expected));
    EXPECT_EQ(expected, output);
  }

  fill = std::string(10, 'A');
  bytes_written = write(fd, fill.data(), fill.size());
  ASSERT_EQ(10, bytes_written);

  // We did not write a newline, the stream should buffer but not write.
  s = nbfs.getline(output);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(10, nbfs.offset());
  EXPECT_TRUE(output.empty());

  // Write another byte and a newline.
  fill = std::string(1, 'A');
  fill.push_back('\n');
  bytes_written = write(fd, fill.data(), fill.size());
  ASSERT_EQ(2, bytes_written);

  // Now the buffer should dequeue.
  s = nbfs.getline(output);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(0, nbfs.offset());

  {
    fill = std::string(11, 'A');
    fill.push_back('\n');
    std::string expected;
    std::copy(fill.begin(), fill.end() - 1, std::back_inserter(expected));
    EXPECT_EQ(expected, output);
  }

  // Nothing to read (failure)
  s = nbfs.getline(output);
  EXPECT_FALSE(s.ok());
  EXPECT_EQ(0, nbfs.offset());

  // Write too much
  fill = std::string(20, 'A');
  fill.push_back('\n');
  bytes_written = write(fd, fill.data(), fill.size());
  ASSERT_EQ(21, bytes_written);

  s = nbfs.getline(output);
  EXPECT_FALSE(s.ok());
  EXPECT_EQ(0, nbfs.offset());

  // Need to clear the newline here.
  s = nbfs.getline(output);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(0, nbfs.offset());

  // Write multiple strings.
  fill = std::string(9, 'A');
  fill.push_back('\n');
  fill += std::string(9, 'A');
  fill.push_back('\n');

  bytes_written = write(fd, fill.data(), fill.size());
  ASSERT_EQ(20, bytes_written);

  // Read the first
  s = nbfs.getline(output);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(10, nbfs.offset());

  {
    std::string expected(9, 'A');
    EXPECT_EQ(expected, output);
  }

  // Read the second
  s = nbfs.getline(output);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(0, nbfs.offset());

  {
    std::string expected(9, 'A');
    EXPECT_EQ(expected, output);
  }
}

TEST_F(SyslogTests, test_populate_event_context) {
  std::string line =
      R"|("2016-03-22T21:17:01.701882+00:00","vagrant-ubuntu-trusty-64","6","cron","CRON[16538]:"," (root) CMD (   cd / && run-parts --report /etc/cron.hourly)")|";
  SyslogEventPublisher pub;
  auto ec = pub.createEventContext();
  Status status = pub.populateEventContext(line, ec);

  ASSERT_TRUE(status.ok());
  // Note: the time-parsing was removed to allow events to auto-assign.
  ASSERT_EQ(0U, ec->time);
  ASSERT_EQ("2016-03-22T21:17:01.701882+00:00", ec->fields.at("datetime"));
  ASSERT_EQ("vagrant-ubuntu-trusty-64", ec->fields.at("host"));
  ASSERT_EQ("6", ec->fields.at("severity"));
  ASSERT_EQ("cron", ec->fields.at("facility"));
  ASSERT_EQ("CRON[16538]", ec->fields.at("tag"));
  ASSERT_EQ("(root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            ec->fields.at("message"));

  // Too few fields

  std::string bad_line =
      R"("2016-03-22T21:17:01.701882+00:00","vagrant-ubuntu-trusty-64","6","cron",)";
  ec = pub.createEventContext();
  status = pub.populateEventContext(bad_line, ec);
  ASSERT_FALSE(status.ok());
  ASSERT_NE(std::string::npos, status.getMessage().find("fewer"));

  // Too many fields
  bad_line = R"("2016-03-22T21:17:01.701882+00:00","","6","","","","")";
  ec = pub.createEventContext();
  status = pub.populateEventContext(bad_line, ec);
  ASSERT_FALSE(status.ok());
  ASSERT_NE(std::string::npos, status.getMessage().find("more"));
}

TEST_F(SyslogTests, test_csv_separator) {
  ASSERT_EQ(std::vector<std::string>({"", "", "", "", ""}), splitCsv(",,,,"));
  ASSERT_EQ(std::vector<std::string>({" ", " ", " ", " ", " "}),
            splitCsv(" , , , , "));
  ASSERT_EQ(std::vector<std::string>({"foo", "bar", "baz"}),
            splitCsv("foo,bar,baz"));
  ASSERT_EQ(std::vector<std::string>({"foo", "bar", "baz"}),
            splitCsv("\"foo\",\"bar\",\"baz\""));
  ASSERT_EQ(std::vector<std::string>({",foo,", ",bar", "baz,"}),
            splitCsv("\",foo,\",\",bar\",\"baz,\""));
  ASSERT_EQ(std::vector<std::string>({",f\\oo,", ",ba\\'r", "baz\\,"}),
            splitCsv("\",f\\oo,\",\",ba\\'r\",\"baz\\,\""));
  ASSERT_EQ(std::vector<std::string>({"\",f\\o\"o,", "\",ba\\'r", "baz\\,\""}),
            splitCsv("\"\"\",f\\o\"\"o,\",\"\"\",ba\\'r\",\"baz\\,\"\"\""));
  ASSERT_EQ(std::vector<std::string>({"\",f\\ø\"o,", "\",bá\\'r", "baz\\,\""}),
            splitCsv("\"\"\",f\\ø\"\"o,\",\"\"\",bá\\'r\",\"baz\\,\"\"\""));
}
}

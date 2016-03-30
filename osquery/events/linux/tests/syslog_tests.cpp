/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>

#include <gtest/gtest.h>

#include <boost/tokenizer.hpp>

#include "osquery/core/test_util.h"
#include "osquery/events/linux/syslog.h"

namespace osquery {

class SyslogTests : public testing::Test {
 public:
  std::vector<std::string> splitCsv(std::string line) {
    boost::tokenizer<RsyslogCsvSeparator> tokenizer(line);
    std::vector<std::string> result(tokenizer.begin(), tokenizer.end());
    return result;
  }
};

TEST_F(SyslogTests, test_populate_event_context) {
  std::string line =
      R"|("2016-03-22T21:17:01.701882+00:00","vagrant-ubuntu-trusty-64","6","cron","CRON[16538]:"," (root) CMD (   cd / && run-parts --report /etc/cron.hourly)")|";
  SyslogEventPublisher pub;
  auto ec = pub.createEventContext();
  Status status = pub.populateEventContext(line, ec);

  ASSERT_TRUE(status.ok());
  ASSERT_EQ((time_t)1458681421, ec->time);
  ASSERT_EQ("vagrant-ubuntu-trusty-64", ec->fields.at("host"));
  ASSERT_EQ("6", ec->fields.at("severity"));
  ASSERT_EQ("cron", ec->fields.at("facility"));
  ASSERT_EQ("CRON[16538]", ec->fields.at("tag"));
  ASSERT_EQ("(root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            ec->fields.at("message"));

  // Too few fields

  std::string bad_line = R"("2016-03-22T21:17:01.701882+00:00","vagrant-ubuntu-trusty-64","6","cron",)";
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

TEST_F(SyslogTests, test_parse_time_string) {
  ASSERT_EQ((time_t)0,
            SyslogEventPublisher::parseTimeString("1970-01-01T00:00:00.000000+00:00"));
  ASSERT_EQ((time_t)1458927568,
            SyslogEventPublisher::parseTimeString("2016-03-25T17:39:28.717070+00:00"));
  ASSERT_EQ((time_t)1483228799,
            SyslogEventPublisher::parseTimeString("2016-12-31T23:59:59.999000+00:00"));
}

TEST_F(SyslogTests, test_csv_separator) {
  ASSERT_EQ(std::vector<std::string>({"", "", "", "", ""}), splitCsv(",,,,"));
  ASSERT_EQ(std::vector<std::string>({" ", " ", " ", " ", " "}),
            splitCsv(" , , , , "));
  ASSERT_EQ(std::vector<std::string>({"foo", "bar", "baz"}),
            splitCsv("foo,bar,baz"));
  ASSERT_EQ(std::vector<std::string>({"foo", "bar", "baz"}),
            splitCsv(R"("foo","bar","baz")"));
  ASSERT_EQ(std::vector<std::string>({",foo,", ",bar", "baz,"}),
            splitCsv(R"(",foo,",",bar","baz,")"));
  ASSERT_EQ(std::vector<std::string>({",f\\oo,", ",ba\\'r", "baz\\,"}),
            splitCsv(R"(",f\oo,",",ba\'r","baz\,")"));
  ASSERT_EQ(std::vector<std::string>({"\",f\\o\"o,", "\",ba\\'r", "baz\\,\""}),
            splitCsv(R"(""",f\o""o,",""",ba\'r","baz\,""")"));
  ASSERT_EQ(std::vector<std::string>({"\",f\\ø\"o,", "\",bá\\'r", "baz\\,\""}),
            splitCsv(R"(""",f\ø""o,",""",bá\'r","baz\,""")"));
}
}

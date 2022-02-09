/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/tables/system/windows/windows_eventlog.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {
class WindowsEventLogTests : public testing::Test {};

TEST_F(WindowsEventLogTests, parse_wel_xml) {
  std::string xml_event =
      "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
      "<System><Provider Name='Application Error'/><EventID "
      "Qualifiers='0'>1000</EventID><Level>2</Level>"
      "<Task>100</Task><Keywords>0x80000000000000</Keywords>"
      "<TimeCreated "
      "SystemTime='2020-08-18T02:45:18.854092300Z'/><EventRecordID>5143</"
      "EventRecordID>"
      "<Channel>Application</Channel><Computer>G1HxG1noIg</Computer><Security/"
      "></System>"
      "<EventData><Data>osqueryi.exe</Data><Data>4.4.0.0</Data>"
      "<Data>5f3b4065</Data><Data>ucrtbased.dll</Data>"
      "<Data>10.0.19041.1</Data><Data>e7caee08</Data>"
      "<Data>c0000005</Data><Data>00000000000c265c</Data>"
      "<Data>b04</Data><Data>01d6750999d2deee</Data>"
      "<Data>C:\\Users\\Administrator\\Documents\\wel_table\\osquery-"
      "wel\\build\\osquery\\Debug\\osqueryi.exe</Data>"
      "<Data>C:\\Windows\\SYSTEM32\\ucrtbased.dll</Data>"
      "<Data>3bcbd6a4-60e5-4474-be94-90c7a987d03b</Data>"
      "<Data></Data><Data></Data></EventData></Event>";

  QueryContext context;
  context.constraints["channel"].add(Constraint(EQUALS, "Application"));
  context.constraints["eventid"].add(Constraint(EQUALS, "1000"));
  context.constraints["timestamp"].add(Constraint(EQUALS, "43200000"));

  Row row;
  parseWelXml(context, stringToWstring(xml_event), row);

  /* NOTE: The escaping of the backslash doesn't match the original xml event
     because JSON is also escaping the backslash, so there are two levels. */
  std::string expect_data =
      "{\"EventData\":[\"osqueryi.exe\",\"4.4.0.0\",\"5f3b4065\",\"ucrtbased."
      "dll\",\"10.0.19041.1\",\"e7caee08\",\"c0000005\",\"00000000000c265c\","
      "\"b04\",\"01d6750999d2deee\","
      "\"C:\\\\Users\\\\Administrator\\\\Documents\\\\wel_table\\\\osquery-"
      "wel\\\\build\\\\osquery\\\\Debug\\\\osqueryi.exe\","
      "\"C:\\\\Windows\\\\SYSTEM32\\\\ucrtbased.dll\",\"3bcbd6a4-60e5-4474-"
      "be94-90c7a987d03b\",\"\",\"\"]}";

  EXPECT_EQ(row["datetime"], "2020-08-18T02:45:18.854092300Z");
  EXPECT_EQ(row["channel"], "Application");
  EXPECT_EQ(row["provider_name"], "Application Error");
  EXPECT_EQ(row["provider_guid"], "");
  EXPECT_EQ(row["eventid"], "1000");
  EXPECT_EQ(row["task"], "100");
  EXPECT_EQ(row["level"], "2");
  EXPECT_EQ(row["keywords"], "0x80000000000000");
  EXPECT_EQ(row["pid"], "-1");
  EXPECT_EQ(row["tid"], "-1");
  EXPECT_EQ(row["data"], expect_data);
}

TEST_F(WindowsEventLogTests, gen_xfilter_test1) {
  QueryContext context;
  std::string xfilter;

  std::string xpath =
      "*[System[(EventID=1000) and (Execution[@ProcessID=0]) and "
      "TimeCreated[@SystemTime&gt;='2020-08-18T00:14:54.000Z' and "
      "@SystemTime&lt;='2020-08-19T00:14:53.999Z']]]";

  context.constraints["channel"].add(Constraint(EQUALS, "Application"));
  context.constraints["eventid"].add(Constraint(EQUALS, "1000"));
  context.constraints["level"].add(Constraint(LESS_THAN, "4"));
  context.constraints["task"].add(Constraint(EQUALS, "0"));
  context.constraints["pid"].add(Constraint(EQUALS, "0"));
  context.constraints["time_range"].add(
      Constraint(EQUALS, "2020-08-18T00:14:54.000Z;2020-08-19T00:14:53.999Z"));

  genXfilterFromConstraints(context, xfilter);
  EXPECT_EQ(xfilter, xpath);
}

TEST_F(WindowsEventLogTests, gen_xfilter_test2) {
  QueryContext context;
  std::string xfilter("");

  std::string xpath =
      "*[System[(EventID=1000) and (Execution[@ProcessID=0]) and "
      "TimeCreated[timediff(@SystemTime) &lt;= 43200000]]]";
  context.constraints["channel"].add(Constraint(EQUALS, "Application"));
  context.constraints["eventid"].add(Constraint(EQUALS, "1000"));
  context.constraints["level"].add(Constraint(LESS_THAN, "4"));
  context.constraints["task"].add(Constraint(EQUALS, "0"));
  context.constraints["pid"].add(Constraint(EQUALS, "0"));
  context.constraints["timestamp"].add(Constraint(EQUALS, "43200000"));

  genXfilterFromConstraints(context, xfilter);
  EXPECT_EQ(xfilter, xpath);
}

} // namespace tables
} // namespace osquery

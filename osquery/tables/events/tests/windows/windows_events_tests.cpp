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

#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/tables/events/windows/windows_events.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace {
const std::vector<std::string> kExpectedOutputFieldList = {"datetime",
                                                           "source",
                                                           "provider_name",
                                                           "provider_guid",
                                                           "computer_name",
                                                           "event_id",
                                                           "task_id",
                                                           "level",
                                                           "keywords",
                                                           "data"};
} // namespace

class WindowsEventsTests : public testing::Test {};

TEST_F(WindowsEventsTests, test_recorded_events) {
  auto input_data_path = boost::filesystem::path(TEST_DATA_PATH) / "input";
  auto folder_found = boost::filesystem::is_directory(input_data_path);
  ASSERT_TRUE(folder_found) << "The input test data directory is not valid";

  auto output_data_path = boost::filesystem::path(TEST_DATA_PATH) / "output";
  folder_found = boost::filesystem::is_directory(output_data_path);
  ASSERT_TRUE(folder_found) << "The output test data directory is not valid";

  for (const auto& event_channel_directory :
       boost::filesystem::directory_iterator(input_data_path)) {
    auto channel_tests_path = event_channel_directory.path().string();
    auto channel_name = event_channel_directory.path().filename();

    for (const auto& event_sample :
         boost::filesystem::directory_iterator(channel_tests_path)) {
      auto event_sample_path = event_sample.path().string();
      auto event_sample_name = event_sample.path().stem();

      // Read the sample file
      std::ifstream file;
      file.open(event_sample_path, std::ios::in);
      ASSERT_TRUE(file);

      auto buffer = std::stringstream();
      buffer << file.rdbuf();
      ASSERT_TRUE(file);

      // The sample event, as exported from the Event Viewer, is nested inside
      // an '<Events>' tag re-export the sample XML without the outer object
      boost::property_tree::ptree event_list;
      read_xml(buffer, event_list);

      auto event_sample_opt = event_list.get_child_optional("Events");
      ASSERT_TRUE(event_sample_opt.has_value())
          << "The following event sample is not valid: " << event_sample_path;

      buffer.str("");
      write_xml(buffer, event_sample_opt.value());

      // Attempt to parse the event sample
      auto wide_chars_buffer = stringToWstring(buffer.str());

      boost::property_tree::ptree event_object = {};
      auto status = parseWindowsEventLogXML(event_object, wide_chars_buffer);

      ASSERT_TRUE(status.ok())
          << "Failed to parse the following event sample: " << event_sample_path
          << ". Error: " << status.getMessage();

      // Attempt to process the event object; this will have to flatten some of
      // the original XML structure to make it compatible with JSON
      WELEvent windows_event;
      status = parseWindowsEventLogPTree(windows_event, event_object);
      ASSERT_TRUE(status.ok())
          << "Failed to process the following event sample: "
          << event_sample_path << ". Error: " << status.getMessage();

      // Read the file containing the expected output and validate it
      auto output_file_path =
          (output_data_path / channel_name / event_sample_name).string() +
          ".json";

      boost::property_tree::ptree expected_event_data = {};
      bool parsing_error = false;

      try {
        read_json(output_file_path, expected_event_data);
      } catch (const boost::property_tree::json_parser::json_parser_error&) {
        parsing_error = true;
      }

      ASSERT_FALSE(parsing_error)
          << "Failed to parse the test data: " << output_file_path;

      for (const auto& expected_field : kExpectedOutputFieldList) {
        auto field_opt = expected_event_data.get_child_optional(expected_field);
        ASSERT_TRUE(field_opt.has_value())
            << "The following test file is missing the " << expected_field
            << " field: " << output_file_path;
      }

      // Compare what we have extracted from the event with the expected output
      EXPECT_NE(windows_event.osquery_time, 0U);
      EXPECT_EQ(windows_event.datetime,
                expected_event_data.get<std::string>("datetime"));

      EXPECT_EQ(windows_event.source,
                expected_event_data.get<std::string>("source"));

      EXPECT_EQ(windows_event.provider_name,
                expected_event_data.get<std::string>("provider_name"));

      EXPECT_EQ(windows_event.provider_guid,
                expected_event_data.get<std::string>("provider_guid"));

      EXPECT_EQ(windows_event.computer_name,
                expected_event_data.get<std::string>("computer_name"));

      EXPECT_EQ(windows_event.event_id,
                expected_event_data.get<int>("event_id"));

      EXPECT_EQ(windows_event.task_id, expected_event_data.get<int>("task_id"));
      EXPECT_EQ(windows_event.level, expected_event_data.get<int>("level"));
      EXPECT_EQ(windows_event.keywords,
                expected_event_data.get<std::string>("keywords"));

      EXPECT_EQ(windows_event.data,
                expected_event_data.get<std::string>("data"));
    }
  }
}

TEST_F(WindowsEventsTests, invalid_event_parsing) {
  boost::property_tree::ptree event_object = {};
  WELEvent windows_event;
  auto status = parseWindowsEventLogPTree(windows_event, event_object);

  ASSERT_FALSE(status.ok());
}

TEST_F(WindowsEventsTests, row_generation) {
  // clang-format off
  WELEvent test_event = {
    // osquery time
    1U,

    "datetime",
    "source",
    "provider_name",
    "provider_guid",
    "computer_name",

    // event id
    1,

    // task id
    2,

    // level
    3,

    // pid
    -1,

    // tid
    -1,

    // keywords
    "4",

    "data"
  };
  // clang-format on

  Row row;
  WindowsEventSubscriber::generateRow(row, test_event);

  ASSERT_EQ(row.size(), 11U);

  EXPECT_EQ(row["time"], "1");
  EXPECT_EQ(row["datetime"], "datetime");
  EXPECT_EQ(row["source"], "source");
  EXPECT_EQ(row["provider_name"], "provider_name");
  EXPECT_EQ(row["provider_guid"], "provider_guid");
  EXPECT_EQ(row["computer_name"], "computer_name");
  EXPECT_EQ(row["eventid"], "1");
  EXPECT_EQ(row["task"], "2");
  EXPECT_EQ(row["level"], "3");
  EXPECT_EQ(row["keywords"], "4");
  EXPECT_EQ(row["data"], "data");
}
} // namespace osquery

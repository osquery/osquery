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

#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/tables/events/windows/powershell_events.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace {
extern const std::string kSingleScriptBlock;
extern const std::string kMultiChunkScript01;
extern const std::string kMultiChunkScript02;
extern const std::string kMultiChunkScript03;

const std::size_t kExpectedColumnCount{8U};

Status initializePowershellEventsContext(
    PowershellEventSubscriber::Context& context,
    const std::vector<std::reference_wrapper<const std::string>>&
        xml_event_list) {
  for (const auto& xml_event : xml_event_list) {
    boost::property_tree::ptree event_object = {};
    auto status =
        parseWindowsEventLogXML(event_object, stringToWstring(xml_event));

    if (!status.ok()) {
      return status;
    }

    PowershellEventSubscriber::processEventObject(context, event_object);
  }

  return Status::success();
}
} // namespace

class PowershellEventsTests : public testing::Test {};

TEST_F(PowershellEventsTests, parse_simple_event) {
  boost::property_tree::ptree event_object = {};
  auto status = parseWindowsEventLogXML(event_object,
                                        stringToWstring(kSingleScriptBlock));

  ASSERT_TRUE(status.ok());

  boost::optional<PowershellEventSubscriber::Context::ScriptMessage>
      script_message_opt;

  status = PowershellEventSubscriber::parseScriptMessageEvent(
      script_message_opt, event_object);

  ASSERT_TRUE(script_message_opt);
  ASSERT_TRUE(status.ok());

  const auto& script_message = script_message_opt.value();

  EXPECT_EQ(script_message.expected_message_count, 1U);
  EXPECT_EQ(script_message.message_number, 1U);

  EXPECT_EQ(script_message.script_block_id,
            "0be6ea7f-ff36-4527-af0d-5125b95be731");

  EXPECT_EQ(script_message.message, "write-host \"1\"");
  EXPECT_NE(script_message.osquery_time, 0U);
  EXPECT_EQ(script_message.event_time, "2020-03-03T03:11:06.252766100Z");
  EXPECT_EQ(script_message.script_path, "C:\\script.ps1");
  EXPECT_EQ(script_message.script_name, "script.ps1");
}

TEST_F(PowershellEventsTests, process_broken_event) {
  PowershellEventSubscriber::Context context;
  boost::property_tree::ptree event_object = {};

  auto status =
      PowershellEventSubscriber::processEventObject(context, event_object);

  EXPECT_FALSE(status.ok());
}

TEST_F(PowershellEventsTests, parse_broken_event) {
  boost::property_tree::ptree event_object = {};
  boost::optional<PowershellEventSubscriber::Context::ScriptMessage>
      script_message_opt;

  auto status = PowershellEventSubscriber::parseScriptMessageEvent(
      script_message_opt, event_object);

  ASSERT_FALSE(status.ok());
  ASSERT_FALSE(script_message_opt);
}

TEST_F(PowershellEventsTests, event_expiration) {
  auto osquery_time = std::time(nullptr) + 10000U;

  PowershellEventSubscriber::Context context;
  context.last_event_expiration_time = osquery_time;

  for (auto i = 0U; i < 10U; ++i) {
    auto script_block_id = "expiring_script_id_" + std::to_string(i);

    PowershellEventSubscriber::Context::ScriptMessage script_message = {};
    script_message.script_block_id = script_block_id;

    PowershellEventSubscriber::Context::ScriptMessageList script_message_list =
        {};

    script_message_list.push_back(std::move(script_message));

    context.script_state_map.insert(
        {script_block_id, std::move(script_message_list)});
  }

  for (auto i = 0U; i < 10U; ++i) {
    auto script_block_id = "non-expiring_script_id_" + std::to_string(i);

    PowershellEventSubscriber::Context::ScriptMessage script_message = {};
    script_message.osquery_time = osquery_time;
    script_message.script_block_id = script_block_id;

    PowershellEventSubscriber::Context::ScriptMessageList script_message_list =
        {};

    script_message_list.push_back(std::move(script_message));

    context.script_state_map.insert(
        {script_block_id, std::move(script_message_list)});
  }

  auto status = PowershellEventSubscriber::processEventExpiration(context);
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(context.script_state_map.size(), 20U);
  EXPECT_EQ(context.expired_event_count, 0U);

  context.last_event_expiration_time = 0;

  status = PowershellEventSubscriber::processEventExpiration(context);
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(context.script_state_map.size(), 10U);
  EXPECT_EQ(context.expired_event_count, 10U);
}

TEST_F(PowershellEventsTests, simple_event_row_emission) {
  PowershellEventSubscriber::Context context;
  auto status = initializePowershellEventsContext(
      context, {std::ref(kSingleScriptBlock)});

  ASSERT_TRUE(status.ok());
  ASSERT_EQ(context.row_list.size(), 1U);

  const auto& row = context.row_list.at(0U);
  ASSERT_EQ(row.size(), kExpectedColumnCount);

  EXPECT_FALSE(row.at("time").empty());
  EXPECT_FALSE(row.at("cosine_similarity").empty());
  EXPECT_EQ(row.at("datetime"), "2020-03-03T03:11:06.252766100Z");
  EXPECT_EQ(row.at("script_block_id"), "0be6ea7f-ff36-4527-af0d-5125b95be731");
  EXPECT_EQ(row.at("script_block_count"), "1");
  EXPECT_EQ(row.at("script_text"), "write-host \"1\"");
  EXPECT_EQ(row.at("script_name"), "script.ps1");
  EXPECT_EQ(row.at("script_path"), "C:\\script.ps1");
}

TEST_F(PowershellEventsTests, trace_simple_event) {
  PowershellEventSubscriber::Context context;
  auto status = initializePowershellEventsContext(
      context, {std::ref(kSingleScriptBlock)});

  ASSERT_TRUE(status.ok());

  ASSERT_EQ(context.row_list.size(), 1U);
  EXPECT_EQ(context.row_list.at(0U).size(), kExpectedColumnCount);

  EXPECT_TRUE(context.script_state_map.empty());
  EXPECT_EQ(context.last_event_expiration_time, 0U);
  EXPECT_EQ(context.invalid_event_count, 0U);
  EXPECT_EQ(context.expired_event_count, 0U);
}

TEST_F(PowershellEventsTests, trace_ordered_complete_split_event) {
  PowershellEventSubscriber::Context context;
  auto status =
      initializePowershellEventsContext(context,
                                        {std::ref(kMultiChunkScript01),
                                         std::ref(kMultiChunkScript02),
                                         std::ref(kMultiChunkScript03)});
  ASSERT_TRUE(status.ok());

  ASSERT_EQ(context.row_list.size(), 1U);
  EXPECT_EQ(context.row_list.at(0U).size(), kExpectedColumnCount);

  EXPECT_TRUE(context.script_state_map.empty());
  EXPECT_EQ(context.last_event_expiration_time, 0U);
  EXPECT_EQ(context.invalid_event_count, 0U);
  EXPECT_EQ(context.expired_event_count, 0U);
}

TEST_F(PowershellEventsTests, trace_unordered_complete_split_event) {
  PowershellEventSubscriber::Context context;
  auto status =
      initializePowershellEventsContext(context,
                                        {std::ref(kMultiChunkScript03),
                                         std::ref(kMultiChunkScript02),
                                         std::ref(kMultiChunkScript01)});
  ASSERT_TRUE(status.ok());

  ASSERT_EQ(context.row_list.size(), 1U);
  EXPECT_EQ(context.row_list.at(0U).size(), kExpectedColumnCount);

  EXPECT_TRUE(context.script_state_map.empty());
  EXPECT_EQ(context.last_event_expiration_time, 0U);
  EXPECT_EQ(context.invalid_event_count, 0U);
  EXPECT_EQ(context.expired_event_count, 0U);
}

TEST_F(PowershellEventsTests, trace_ordered_incomplete_split_event) {
  PowershellEventSubscriber::Context context;
  auto status = initializePowershellEventsContext(
      context, {std::ref(kMultiChunkScript01), std::ref(kMultiChunkScript03)});
  ASSERT_TRUE(status.ok());

  EXPECT_TRUE(context.row_list.empty());

  EXPECT_EQ(context.script_state_map.size(), 1U);
  EXPECT_EQ(context.last_event_expiration_time, 0U);
  EXPECT_EQ(context.invalid_event_count, 0U);
  EXPECT_EQ(context.expired_event_count, 0U);
}

TEST_F(PowershellEventsTests, trace_unordered_incomplete_split_event) {
  PowershellEventSubscriber::Context context;

  auto status = initializePowershellEventsContext(
      context, {std::ref(kMultiChunkScript03), std::ref(kMultiChunkScript01)});

  ASSERT_TRUE(status.ok());

  EXPECT_TRUE(context.row_list.empty());

  EXPECT_EQ(context.script_state_map.size(), 1U);
  EXPECT_EQ(context.last_event_expiration_time, 0U);
  EXPECT_EQ(context.invalid_event_count, 0U);
  EXPECT_EQ(context.expired_event_count, 0U);
}

TEST_F(PowershellEventsTests, trace_invalid_event) {
  const std::string empty_string;
  const std::string invalid_tag{"<dummy_tag></dummy_tag>"};

  PowershellEventSubscriber::Context context;
  auto status =
      initializePowershellEventsContext(context, {empty_string, invalid_tag});

  ASSERT_TRUE(status.ok());
  EXPECT_TRUE(context.row_list.empty());

  EXPECT_EQ(context.script_state_map.size(), 0U);
  EXPECT_EQ(context.last_event_expiration_time, 0U);
  EXPECT_EQ(context.invalid_event_count, 2U);
  EXPECT_EQ(context.expired_event_count, 0U);
}

namespace {
// clang-format off
const std::string kSingleScriptBlock{
  "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
      "<Provider Name='Microsoft-Windows-PowerShell' Guid='{a0c1853b-5c40-4b15-8766-3cf1c58f985a}'/>"
      "<EventID>4104</EventID>"
      "<Version>1</Version>"
      "<Level>5</Level>"
      "<Task>2</Task>"
      "<Opcode>15</Opcode>"
      "<Keywords>0x0</Keywords>"
      "<TimeCreated SystemTime='2020-03-03T03:11:06.252766100Z'/>"
      "<EventRecordID>1076</EventRecordID>"
      "<Correlation ActivityID='{391f2712-f104-0001-e9ab-1f3904f1d501}'/>"
      "<Execution ProcessID='8040' ThreadID='7680'/>"
      "<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
      "<Computer>DESKTOP-CPH90KV</Computer>"
      "<Security UserID='S-1-5-21-2526451620-379595376-1515827217-1001'/>"
    "</System>"
    "<EventData>"
      "<Data Name='MessageNumber'>1</Data>"
      "<Data Name='MessageTotal'>1</Data>"
      "<Data Name='ScriptBlockText'>write-host \"1\"</Data>"
      "<Data Name='ScriptBlockId'>0be6ea7f-ff36-4527-af0d-5125b95be731</Data>"
      "<Data Name='Path'>C:\\script.ps1</Data>"
    "</EventData>"
  "</Event>"
};
// clang-format on

// clang-format off
const std::string kMultiChunkScript01{
  "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
      "<Provider Name='Microsoft-Windows-PowerShell' Guid='{a0c1853b-5c40-4b15-8766-3cf1c58f985a}'/>"
      "<EventID>4104</EventID>"
      "<Version>1</Version>"
      "<Level>5</Level>"
      "<Task>2</Task>"
      "<Opcode>15</Opcode>"
      "<Keywords>0x0</Keywords>"
      "<TimeCreated SystemTime='2020-03-03T03:07:32.478787500Z'/>"
      "<EventRecordID>1023</EventRecordID>"
      "<Correlation ActivityID='{391f2712-f104-0001-bba9-1f3904f1d501}'/>"
      "<Execution ProcessID='8040' ThreadID='7680'/>"
      "<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
      "<Computer>DESKTOP-CPH90KV</Computer>"
      "<Security UserID='S-1-5-21-2526451620-379595376-1515827217-1001'/>"
    "</System>"
    "<EventData>"
      "<Data Name='MessageNumber'>1</Data>"
      "<Data Name='MessageTotal'>3</Data>"
      "<Data Name='ScriptBlockText'>write-host \"1\"</Data>"
      "<Data Name='ScriptBlockId'>6abeb3fd-1f15-41b5-93cf-a54fff8f905b</Data>"
      "<Data Name='Path'></Data>"
    "</EventData>"
  "</Event>"
};
// clang-format on

// clang-format off
const std::string kMultiChunkScript02{
  "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
      "<Provider Name='Microsoft-Windows-PowerShell' Guid='{a0c1853b-5c40-4b15-8766-3cf1c58f985a}'/>"
      "<EventID>4104</EventID>"
      "<Version>1</Version>"
      "<Level>5</Level>"
      "<Task>2</Task>"
      "<Opcode>15</Opcode>"
      "<Keywords>0x0</Keywords>"
      "<TimeCreated SystemTime='2020-03-03T03:07:32.478832600Z'/>"
      "<EventRecordID>1024</EventRecordID>"
      "<Correlation ActivityID='{391f2712-f104-0001-bba9-1f3904f1d501}'/>"
      "<Execution ProcessID='8040' ThreadID='7680'/>"
      "<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
      "<Computer>DESKTOP-CPH90KV</Computer>"
      "<Security UserID='S-1-5-21-2526451620-379595376-1515827217-1001'/>"
    "</System>"
    "<EventData>"
      "<Data Name='MessageNumber'>2</Data>"
      "<Data Name='MessageTotal'>3</Data>"
      "<Data Name='ScriptBlockText'>write-host \"2\"</Data>"
      "<Data Name='ScriptBlockId'>6abeb3fd-1f15-41b5-93cf-a54fff8f905b</Data>"
      "<Data Name='Path'></Data>"
    "</EventData>"
  "</Event>"
};
// clang-format on

// clang-format off
const std::string kMultiChunkScript03{
  "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
      "<Provider Name='Microsoft-Windows-PowerShell' Guid='{a0c1853b-5c40-4b15-8766-3cf1c58f985a}'/>"
      "<EventID>4104</EventID>"
      "<Version>1</Version>"
      "<Level>5</Level>"
      "<Task>2</Task>"
      "<Opcode>15</Opcode>"
      "<Keywords>0x0</Keywords>"
      "<TimeCreated SystemTime='2020-03-03T03:07:32.478832600Z'/>"
      "<EventRecordID>1025</EventRecordID>"
      "<Correlation ActivityID='{391f2712-f104-0001-bba9-1f3904f1d501}'/>"
      "<Execution ProcessID='8040' ThreadID='7680'/>"
      "<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
      "<Computer>DESKTOP-CPH90KV</Computer>"
      "<Security UserID='S-1-5-21-2526451620-379595376-1515827217-1001'/>"
    "</System>"
    "<EventData>"
      "<Data Name='MessageNumber'>3</Data>"
      "<Data Name='MessageTotal'>3</Data>"
      "<Data Name='ScriptBlockText'>write-host \"3\"</Data>"
      "<Data Name='ScriptBlockId'>6abeb3fd-1f15-41b5-93cf-a54fff8f905b</Data>"
      "<Data Name='Path'></Data>"
    "</EventData>"
  "</Event>"
};
// clang-format on
} // namespace
} // namespace osquery

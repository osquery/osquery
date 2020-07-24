/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/tables/events/windows/windows_events.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace {
std::string normalizeChannelName(std::string channel) {
  boost::erase_all(channel, "\"");
  boost::erase_all(channel, "\'");

  std::transform(channel.begin(), channel.end(), channel.begin(), ::tolower);
  return channel;
}
} // namespace

FLAG(bool,
     enable_windows_events_subscriber,
     false,
     "Enables Windows Event Log events");

FLAG(string,
     windows_event_channels,
     "System,Application,Setup,Security",
     "Comma-separated list of Windows event log channels");

DECLARE_bool(enable_windows_events_publisher);

REGISTER(WindowsEventSubscriber, "event_subscriber", "windows_events");

Status WindowsEventSubscriber::init() {
  if (!FLAGS_enable_windows_events_publisher) {
    return Status::failure("Required publisher is disabled by configuration");
  }

  if (!FLAGS_enable_windows_events_subscriber) {
    return Status::failure("Subscriber disabled by configuration");
  }

  auto subscription_context = createSubscriptionContext();
  for (auto channel : osquery::split(FLAGS_windows_event_channels, ",")) {
    auto normalized_channel_name = normalizeChannelName(channel);
    subscription_context->channel_list.insert(normalized_channel_name);
  }

  subscribe(&WindowsEventSubscriber::Callback, subscription_context);
  return Status::success();
}

WindowsEventSubscriber::~WindowsEventSubscriber() {}

Status WindowsEventSubscriber::Callback(const ECRef& event, const SCRef&) {
  std::vector<Event> windows_event_list;
  bool display_parsing_error{false};

  for (const auto& event_object : event->event_objects) {
    Event windows_event = {};
    auto status = processEventObject(windows_event, event_object);
    if (!status.ok()) {
      display_parsing_error = true;
      LOG(ERROR) << status.getMessage();
      continue;
    }

    windows_event_list.push_back(std::move(windows_event));
  }

  if (display_parsing_error) {
    LOG(ERROR) << "Failed to process a Windows event log object";
  }

  if (windows_event_list.empty()) {
    return Status::success();
  }

  std::vector<Row> row_list;

  for (const auto& windows_event : windows_event_list) {
    Row row = {};
    generateRow(row, windows_event);

    row_list.push_back(std::move(row));
  }

  if (!row_list.empty()) {
    addBatch(row_list);
  }

  return Status::success();
}

Status WindowsEventSubscriber::processEventObject(
    Event& windows_event, const boost::property_tree::ptree& event_object) {
  windows_event = {};

  Event output;
  output.osquery_time = std::time(nullptr);

  output.datetime =
      event_object.get("Event.System.TimeCreated.<xmlattr>.SystemTime", "");

  if (output.datetime.empty()) {
    return Status::failure(
        "Invalid Windows event object: the TimeCreated::SystemTime attribute "
        "is missing or not valid");
  }

  output.source = event_object.get("Event.System.Channel", "");
  if (output.source.empty()) {
    return Status::failure(
        "Invalid Windows event object: the Event.System.Channel tag is missing "
        "or not valid");
  }

  output.provider_name =
      event_object.get("Event.System.Provider.<xmlattr>.Name", "");

  if (output.provider_name.empty()) {
    return Status::failure(
        "Invalid Windows event object: the Provider::Name attribute is missing "
        "or not valid");
  }

  // This field may be missing
  output.provider_guid =
      event_object.get("Event.System.Provider.<xmlattr>.Guid", "");

  output.event_id = event_object.get("Event.System.EventID", -1);
  if (output.event_id == -1) {
    return Status::failure(
        "Invalid Windows event object: the System.EventID tag is missing or "
        "not valid");
  }

  output.task_id = event_object.get("Event.System.Task", -1);
  if (output.task_id == -1) {
    return Status::failure(
        "Invalid Windows event object: the System.Task tag is missing or not "
        "valid");
  }

  output.level = event_object.get("Event.System.Level", -1);
  if (output.level == -1) {
    return Status::failure(
        "Invalid Windows event object: the System.Level tag is missing or not "
        "valid");
  }

  // These values will easily go above what an std::int64_t can represent, and
  // sqlite does not have an unsigned version for sqlite3_result_int64
  output.keywords = event_object.get("Event.System.Keywords", "");

  auto event_data_node_opt = event_object.get_child_optional("Event.EventData");
  boost::property_tree::ptree event_data;

  if (event_data_node_opt) {
    const auto& event_data_node = event_data_node_opt.value();

    bool detect_data_type{true};
    bool as_array{false};

    for (const auto& p : event_data_node) {
      const auto& name = p.first;
      const auto& data_field = p.second;

      if (name != "Data") {
        continue;
      }

      std::string data_name = {};

      auto data_name_attr_opt = data_field.get_child_optional("<xmlattr>.Name");
      if (data_name_attr_opt.has_value()) {
        const auto& data_name_attr = data_name_attr_opt.value();
        data_name = data_name_attr.get_value<std::string>("");
      }

      if (detect_data_type) {
        as_array = data_name.empty();
        detect_data_type = false;
      }

      if (as_array != data_name.empty()) {
        return Status::failure(
            "Invalid Windows event object: found both named and unnamed <Data> "
            "tags under <EventData>");
      }

      auto data_value = data_field.get("", "");

      if (as_array) {
        boost::property_tree::ptree array_item;
        array_item.put("", data_value);

        event_data.push_back(std::make_pair("", array_item));

      } else {
        event_data.put(data_name, data_value);
      }
    }
  }

  // We only support the Data tags for now, but make sure we can add
  // additional fields in the future
  boost::property_tree::ptree property_list;
  property_list.add_child("Data", event_data);

  try {
    std::stringstream stream;
    boost::property_tree::write_json(stream, property_list, false);

    output.data = stream.str();

  } catch (const boost::property_tree::json_parser::json_parser_error& e) {
    return Status::failure(
        "Invalid Windows event object: the EventData tag is not valid: " +
        e.message());
  }

  if (output.data.empty()) {
    return Status::failure(
        "Invalid Windows event object: the EventData output is empty");
  }

  output.data.pop_back();

  windows_event = std::move(output);
  return Status::success();
}

void WindowsEventSubscriber::generateRow(Row& row, const Event& windows_event) {
  row = {};

  row["time"] = INTEGER(windows_event.osquery_time);
  row["datetime"] = SQL_TEXT(windows_event.datetime);
  row["source"] = SQL_TEXT(windows_event.source);
  row["provider_name"] = SQL_TEXT(windows_event.provider_name);
  row["provider_guid"] = SQL_TEXT(windows_event.provider_guid);
  row["eventid"] = INTEGER(windows_event.event_id);
  row["task"] = INTEGER(windows_event.task_id);
  row["level"] = INTEGER(windows_event.level);
  row["keywords"] = SQL_TEXT(windows_event.keywords);
  row["data"] = SQL_TEXT(windows_event.data);
}
} // namespace osquery

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core/flags.h>
#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace pt = boost::property_tree;

namespace osquery {

static inline pt::ptree parseChildNodeToJSONPtree(
    const pt::ptree& event_data_node) {
  pt::ptree event_data;
  bool detect_data_type{true};
  bool as_array{false};

  for (const auto& p : event_data_node) {
    const auto& name = p.first;
    const auto& data_field = p.second;

    if (name == "Data") {
      pt::ptree array_item;
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

      auto data_value = data_field.get("", "");
      if (as_array) {
        array_item.put("", data_value);
        event_data.push_back(std::make_pair("", array_item));
      } else {
        event_data.put(data_name, data_value);
      }

    } else {
      // Process xml tags if they are not Data.
      // Check if the `data_field` has no children and get
      // the data_value
      if (data_field.empty()) {
        pt::ptree array_item;
        auto data_value = data_field.get("", "");
        array_item.put("", data_value);
        event_data.add_child(name, array_item);
      } else {
        pt::ptree array_item;
        auto child = parseChildNodeToJSONPtree(data_field);
        event_data.add_child(name, child);
      }
    }
  }
  return event_data;
}

Status parseWindowsEventLogXML(pt::ptree& event_object,
                               const std::wstring& xml_event) {
  event_object = {};

  try {
    auto converted_xml_event = wstringToString(xml_event.c_str());
    std::stringstream stream(std::move(converted_xml_event));

    pt::ptree output;
    read_xml(stream, output);

    event_object = std::move(output);

  } catch (const pt::xml_parser::xml_parser_error& e) {
    return Status::failure("Failed to parse the XML event: " + e.message());
  }

  return Status::success();
}

Status parseWindowsEventLogPTree(WELEvent& windows_event,
                                 const pt::ptree& event_object) {
  windows_event = {};

  WELEvent output;
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

  output.computer_name = event_object.get("Event.System.Computer", "");
  if (output.computer_name.empty()) {
    return Status::failure(
        "Invalid Windows event object: the Event.System.Computer tag is "
        "missing "
        "or not valid");
  }

  output.level = event_object.get("Event.System.Level", -1);
  if (output.level == -1) {
    return Status::failure(
        "Invalid Windows event object: the System.Level tag is missing or not "
        "valid");
  }

  // Some events may not have associated ProcessID and ThreadID; fallback value
  // is set to -1
  output.pid =
      event_object.get("Event.System.Execution.<xmlattr>.ProcessID", -1);
  output.tid =
      event_object.get("Event.System.Execution.<xmlattr>.ThreadID", -1);

  // These values will easily go above what an std::int64_t can represent, and
  // sqlite does not have an unsigned version for sqlite3_result_int64
  output.keywords = event_object.get("Event.System.Keywords", "");

  pt::ptree property_list;
  auto getDataFromPtree = [&](std::string node_name) -> void {
    auto event_data_node_opt = event_object.get_child_optional(node_name);
    if (!event_data_node_opt) {
      return;
    }

    const auto& event_data_node = event_data_node_opt.value();
    auto event_data = parseChildNodeToJSONPtree(event_data_node);
    property_list.add_child(node_name, event_data);
  };

  // Add the event & user data node to the property list
  getDataFromPtree("Event.EventData");
  getDataFromPtree("Event.UserData");

  try {
    std::stringstream stream;
    pt::write_json(stream, property_list.get_child("Event"), false);

    output.data = stream.str();

  } catch (const pt::json_parser::json_parser_error& e) {
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
} // namespace osquery

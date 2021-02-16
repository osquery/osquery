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

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
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
  std::vector<WELEvent> windows_event_list;
  bool display_parsing_error{false};

  for (const auto& event_object : event->event_objects) {
    WELEvent windows_event = {};
    auto status = parseWindowsEventLogPTree(windows_event, event_object);
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

void WindowsEventSubscriber::generateRow(Row& row,
                                         const WELEvent& windows_event) {
  row = {};

  row["time"] = INTEGER(windows_event.osquery_time);
  row["datetime"] = SQL_TEXT(windows_event.datetime);
  row["source"] = SQL_TEXT(windows_event.source);
  row["provider_name"] = SQL_TEXT(windows_event.provider_name);
  row["provider_guid"] = SQL_TEXT(windows_event.provider_guid);
  row["computer_name"] = SQL_TEXT(windows_event.computer_name);
  row["eventid"] = INTEGER(windows_event.event_id);
  row["task"] = INTEGER(windows_event.task_id);
  row["level"] = INTEGER(windows_event.level);
  row["keywords"] = SQL_TEXT(windows_event.keywords);
  row["data"] = SQL_TEXT(windows_event.data);
}
} // namespace osquery

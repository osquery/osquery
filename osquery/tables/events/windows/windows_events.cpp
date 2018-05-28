/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_event_log.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

/*
 * @brief the Windows Event log channels to subscribe to
 *
 * By default we subscribe to all system channels. To subscribe to additional
 * channels specify them via this flag as a comma separated list.
 */
FLAG(string,
     windows_event_channels,
     "System,Application,Setup,Security",
     "Comma-separated list of Windows event log channels");

class WindowsEventSubscriber
    : public EventSubscriber<WindowsEventLogEventPublisher> {
 public:
  Status init() override {
    auto wc = createSubscriptionContext();
    for (auto& chan : osquery::split(FLAGS_windows_event_channels, ",")) {
      // We remove quotes if they exist
      boost::erase_all(chan, "\"");
      boost::erase_all(chan, "\'");
      wc->sources.insert(stringToWstring(chan));
    }
    subscribe(&WindowsEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(WindowsEventSubscriber, "event_subscriber", "windows_events");

/// Helper function to recursively parse a boost ptree
void parseTree(const pt::ptree& tree, std::map<std::string, std::string>& res) {
  for (const auto& node : tree) {
    // Skip this since it's not actually part of the EventData. Also prevents
    // us from adding every Name attribute into its own key invalidly. This is
    // part of a quirk of boost::ptree and its parsing of XML.
    if (node.first == "<xmlattr>") {
      continue;
    }

    auto nodeName = node.second.get("<xmlattr>.Name", "");
    if (nodeName.empty()) {
      nodeName = node.first.empty() ? "DataElement" : node.first;
    }

    res[nodeName] = res[nodeName].empty()
                        ? node.second.data()
                        : res[nodeName] + "," + node.second.data();

    parseTree(node.second, res);
  }
}

Status WindowsEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  FILETIME cTime;
  GetSystemTimeAsFileTime(&cTime);
  r["time"] = BIGINT(filetimeToUnixtime(cTime));
  r["datetime"] =
      ec->eventRecord.get("Event.System.TimeCreated.<xmlattr>.SystemTime", "");
  r["source"] = ec->eventRecord.get("Event.System.Channel", "");
  r["provider_name"] =
      ec->eventRecord.get("Event.System.Provider.<xmlattr>.Name", "");
  r["provider_guid"] =
      ec->eventRecord.get("Event.System.Provider.<xmlattr>.Guid", "");
  r["eventid"] = INTEGER(ec->eventRecord.get("Event.System.EventID", -1));
  r["task"] = INTEGER(ec->eventRecord.get("Event.System.Task", -1));
  r["level"] = INTEGER(ec->eventRecord.get("Event.System.Level", -1));
  r["keywords"] = BIGINT(ec->eventRecord.get("Event.System.Keywords", -1));

  /*
   * From the MSDN definition of the Event Schema, each event will have
   * an XML choice element containing the event data, if any. The first
   * iteration enumerates this choice, and the second iteration enumerates
   * all data elements belonging to the choice.
   */
  pt::ptree jsonOut;
  std::map<std::string, std::string> results;
  std::string eventDataType;

  for (const auto& node : ec->eventRecord.get_child("Event", pt::ptree())) {
    /// We have already processed the System event data above
    if (node.first == "System" || node.first == "<xmlattr>") {
      continue;
    }
    eventDataType = node.first;
    parseTree(node.second, results);
  }
  for (const auto& val : results) {
    /// Reconstruct the event format as much as possible
    jsonOut.put(eventDataType + "." + val.first, val.second);
  }

  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonOut, false);

  auto s = ss.str();
  if (s.at(s.size() - 1) == '\n') {
    s.erase(s.end());
  }
  r["data"] = s;

  add(r);
  return Status(0, "OK");
}
}

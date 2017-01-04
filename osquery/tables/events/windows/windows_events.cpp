/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <boost/property_tree/xml_parser.hpp>
#include <osquery/core/conversions.h>
#include <osquery/core/json.h>
#include <osquery/core/windows/wmi.h>

#include "osquery/events/windows/windows_event_log.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(uint64,
     windows_events_expiry,
     60 * 60 * 24 * 30, // Keep 30 days by default
     "Timeout to expire event subscriber results");

FLAG(uint64,
     windows_events_max,
     100000,
     "Maximum number of events per type to buffer");

FLAG(string,
     additional_windows_event_channels,
     "",
     "Additional Windows event log channels to subscribe to");

class WindowsEventSubscriber
    : public EventSubscriber<WindowsEventLogEventPublisher> {
 public:
  Status init() override {
    WindowsEventLogSubscriptionContextRef wc = createSubscriptionContext();
    for (const auto& tok :
         osquery::split(FLAGS_additional_windows_event_channels, ",")) {
      defaultSubscriptionChannels.insert(stringToWstring(tok));
    }
    wc->sources = this->defaultSubscriptionChannels;
    subscribe(&WindowsEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  size_t getEventsExpiry() override {
    return FLAGS_windows_events_expiry;
  }

  size_t getEventsMax() override {
    return FLAGS_windows_events_max;
  }

  Status Callback(const ECRef& ec, const SCRef& sc);

 private:
  /*
   * @brief the Windows Event log channels to subscribe to
   *
   * By default we subscribe to all system channels. To subscribe to additional
   * channels one can hand them as a comma separated string to the
   * --additional_windows_event_channels flag.
   */
  std::set<std::wstring> defaultSubscriptionChannels = {
      L"System",
      L"Application",
      L"Setup",
      L"Security",
      L"Windows PowerShell",
      L"Hardware Events",
      L"Internet Explorer",
      L"Key Management Service",
      L"PreEmptive",
      L"Texus",
      L"ThinPrint Diagnostics",
  };
};

REGISTER(WindowsEventSubscriber, "event_subscriber", "windows_events");

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

  pt::ptree jsonOut;
  auto data = ec->eventRecord.get_child("Event.EventData");
  for (pt::ptree::const_iterator iter = data.begin(); iter != data.end();
       ++iter) {
    jsonOut.put(iter->second.get("<xmlattr>.Name", "Data"),
                iter->second.data());
  }
  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonOut);
  r["data"] = ss.str();

  add(r);
  return Status(0, "OK");
}
}

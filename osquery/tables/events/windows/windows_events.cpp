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
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_event_log.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(string,
     windows_event_additional_channels,
     "",
     "Comma-separated list of additional Windows event log channels");

/*
* @brief the Windows Event log channels to subscribe to
*
* By default we subscribe to all system channels. To subscribe to additional
* channels one can hand them as a comma separated string to the
* --windows_event_additional_channels flag.
*/
const std::set<std::wstring> kDefaultSubscriptionChannels = {
    L"System", L"Application", L"Setup", L"Security",
};

class WindowsEventSubscriber
    : public EventSubscriber<WindowsEventLogEventPublisher> {
 public:
  Status init() override {
    auto wc = createSubscriptionContext();
    for (const auto& chan :
         osquery::split(FLAGS_windows_event_additional_channels, ",")) {
      wc->sources.insert(stringToWstring(chan));
    }
    for (const auto& chan : kDefaultSubscriptionChannels) {
      wc->sources.insert(chan);
    }
    subscribe(&WindowsEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
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

  /*
   * From the MSDN definition of the Event Schema, each event will have
   * an XML choice element containing the event data, if any. The first
   * iteration enumerates this choice, and the second iteration enumerates
   * all data elements belonging to the choice.
   */
  pt::ptree jsonOut;
  auto eventTypes = ec->eventRecord.get_child("Event", pt::ptree());
  for (const auto& evt : eventTypes) {
    for (const auto& iter : evt.second) {
      jsonOut.put(iter.second.get("<xmlattr>.Name", "DataElement"),
                  iter.second.data());
    }
  }

  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonOut);
  r["data"] = ss.str();

  add(r);
  return Status(0, "OK");
}
}

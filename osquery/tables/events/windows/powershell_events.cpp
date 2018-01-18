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
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_event_log.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

void parseTree(const pt::ptree& tree, std::map<std::string, std::string>& res);

class PowershellEventSubscriber
    : public EventSubscriber<WindowsEventLogEventPublisher> {
 public:
  Status init() override {
    auto wc = createSubscriptionContext();
    wc->sources.insert(
        stringToWstring("microsoft-windows-powershell/operational"));

    subscribe(&PowershellEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(PowershellEventSubscriber, "event_subscriber", "powershell_events");

Status PowershellEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  FILETIME cTime;
  GetSystemTimeAsFileTime(&cTime);
  r["time"] = BIGINT(filetimeToUnixtime(cTime));
  r["datetime"] =
      ec->eventRecord.get("Event.System.TimeCreated.<xmlattr>.SystemTime", "");

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
  r["script_block_id"] = results["ScriptBlockId"];
  r["message_number"] = results["MessageNumber"];
  r["message_total"] = results["MessageTotal"];
  r["script_name"] = results["Name"];
  r["script_path"] = results["Path"];
  r["script_block_text"] = results["ScriptBlockText"];

  add(r);
  return Status(0, "OK");
}
}

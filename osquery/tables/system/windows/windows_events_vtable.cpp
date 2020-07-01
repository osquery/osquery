/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <Windows.h>
#include <winevt.h>

#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kEventLogXmlPrefix = "<QueryList><Query Id=\"0\">";
const std::string kEventLogXmlSuffix = "</Query></QueryList>";

const int kNumEventsBlock = 1024;

/// Helper function to recursively parse a boost property tree
void parseTree(const pt::ptree& tree, std::map<std::string, std::string>& res) {
  for (const auto& node : tree) {
    // Skip this since it's not part of the EventData.
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

void parseWelXml(pt::ptree& propTree, Row& r) {
  r["channel"] = propTree.get("Event.System.Channel", "");
  r["datetime"] =
      propTree.get("Event.System.TimeCreated.<xmlattr>.SystemTime", "");
  r["eventid"] = INTEGER(propTree.get("Event.System.EventID", -1));
  r["recordid"] = INTEGER(propTree.get("Event.System.RecordID", -1));
  r["provider_name"] = propTree.get("Event.System.Provider.<xmlattr>.Name", "");
  r["provider_guid"] = propTree.get("Event.System.Provider.<xmlattr>.Guid", "");
  r["task"] = INTEGER(propTree.get("Event.System.Task", -1));
  r["level"] = INTEGER(propTree.get("Event.System.Level", -1));
  r["keywords"] = propTree.get("Event.System.Keywords", "");

  r["pid"] =
      INTEGER(propTree.get("Event.System.Execution.<xmlattr>.ProcessID", -1));
  r["tid"] =
      INTEGER(propTree.get("Event.System.Execution.<xmlattr>.ThreadID", -1));

  pt::ptree jsonString;
  std::map<std::string, std::string> results;
  std::string eventDataType;

  for (const auto& node : propTree.get_child("Event", pt::ptree())) {
    /// We have already processed the System event data
    if (node.first == "System" || node.first == "<xmlattr>") {
      continue;
    }
    eventDataType = node.first;
    parseTree(node.second, results);
  }
  for (const auto& val : results) {
    jsonString.put(eventDataType + "." + val.first, val.second);
  }

  std::stringstream ss_data;
  boost::property_tree::write_json(ss_data, jsonString, false);

  auto str_data = ss_data.str();
  if (!str_data.empty() && str_data.at(str_data.size() - 1) == '\n') {
    str_data.erase(str_data.end() - 1);
  }
  r["data"] = str_data;
}

void parseQueryResults(QueryContext& context,
                       EVT_HANDLE queryResults,
                       QueryData& results) {
  std::vector<EVT_HANDLE> events(kNumEventsBlock);
  unsigned long numEvents = 0;

  // Retrieve the events one block at a time
  auto ret = EvtNext(
      queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);

  while (ret != FALSE) {
    for (unsigned long i = 0; i < numEvents; i++) {
      std::vector<wchar_t> renderedContent;
      unsigned long renderedBuffSize = 0;
      unsigned long renderedBuffUsed = 0;
      unsigned long propCount = 0;
      EvtRender(nullptr,
                events[i],
                EvtRenderEventXml,
                renderedBuffSize,
                renderedContent.data(),
                &renderedBuffUsed,
                &propCount);

      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        renderedBuffSize = renderedBuffUsed;
        renderedContent.resize(renderedBuffSize);
        EvtRender(nullptr,
                  events[i],
                  EvtRenderEventXml,
                  renderedBuffSize,
                  renderedContent.data(),
                  &renderedBuffUsed,
                  &propCount);
      }
      if (GetLastError() != ERROR_SUCCESS) {
        LOG(WARNING) << "Failed to render windows event with "
                     << GetLastError();
        continue;
      }

      Row r;
      pt::ptree propTree;
      std::stringstream ss;
      ss << wstringToString(renderedContent.data());
      pt::read_xml(ss, propTree);
      parseWelXml(propTree, r);

      // Update the hidden time_range and timestamps column to avoid
      // discarding the table silently.
      auto time_range = context.constraints["time_range"].getAll(EQUALS);
      for (const auto& filter : time_range) {
        r["time_range"] = filter;
      }

      auto timestamp = context.constraints["timestamp"].getAll(EQUALS);
      for (const auto& ts : timestamp) {
        r["timestamp"] = ts;
      }

      results.push_back(r);
      EvtClose(events[i]);
    }

    ret = EvtNext(
        queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);
  }
}

void genXfilterFromConstraints(QueryContext& context, std::string& xfilter) {
  std::vector<std::string> xfilterList;

  auto eids = context.constraints["eventid"].getAll(EQUALS);
  if (!eids.empty()) {
    xfilterList.emplace_back("(EventID=" + osquery::join(eids, " or EventID=") +
                             ")");
  }

  auto tasks = context.constraints["task"].getAll(EQUALS);
  if (!tasks.empty()) {
    xfilterList.emplace_back("(Task=" + osquery::join(tasks, " or Task=") +
                             ")");
  }

  auto levels = context.constraints["level"].getAll(EQUALS);
  if (!levels.empty()) {
    xfilterList.emplace_back("(Level=" + osquery::join(levels, " or Level=") +
                             ")");
  }

  auto pids = context.constraints["pid"].getAll(EQUALS);
  if (!pids.empty()) {
    xfilterList.emplace_back(
        "(Execution[@ProcessID=" +
        osquery::join(pids, "]) or (Execution[@ProcessID=") + "])");
  }

  auto times = context.constraints["time_range"].getAll(EQUALS);
  auto timestamps = context.constraints["timestamp"].getAll(EQUALS);
  if (!times.empty()) {
    for (const auto& t : times) {
      auto time_vec = osquery::split(t, ";");
      if (time_vec.empty()) {
        continue;
      }

      if (time_vec.size() == 1) {
        auto _start = time_vec.front();
        xfilterList.emplace_back("TimeCreated[@SystemTime&gt;='" + _start +
                                 "']");
      } else {
        auto _start = time_vec.front();
        auto _end = time_vec.at(1);
        xfilterList.emplace_back("TimeCreated[@SystemTime&gt;='" + _start +
                                 "' and @SystemTime&lt;='" + _end + "']");
      }
    }
  } else if (!timestamps.empty()) {
    for (const auto& time_diff : timestamps) {
      xfilterList.emplace_back(
          "TimeCreated[timediff(@SystemTime) &lt;= " + time_diff + "]");
    }
  }

  xfilter = xfilterList.empty()
                ? "*"
                : "*[System[" + osquery::join(xfilterList, " and ") + "]]";
}

QueryData genWindowsEventLog(QueryContext& context) {
  QueryData results;

  if (!context.hasConstraint("channel", EQUALS)) {
    LOG(WARNING) << "must specify the event log channel to search";
    return {};
  }

  std::string xfilter("");
  genXfilterFromConstraints(context, xfilter);

  std::string welSearchQuery = kEventLogXmlPrefix;
  auto channels = context.constraints["channel"].getAll(EQUALS);

  for (const auto& channel : channels) {
    welSearchQuery += "<Select Path=\"" + channel + "\">";
    welSearchQuery += xfilter;
    welSearchQuery += "</Select>" + kEventLogXmlSuffix;
    auto queryResults =
        EvtQuery(nullptr,
                 stringToWstring(channel).c_str(),
                 stringToWstring(welSearchQuery).c_str(),
                 EvtQueryChannelPath | EvtQueryReverseDirection);

    if (queryResults == nullptr) {
      LOG(WARNING) << "Failed to search event log for query with "
                   << GetLastError();
      return {};
    }

    parseQueryResults(context, queryResults, results);
    EvtClose(queryResults);
  }

  return results;
}

}; // namespace tables
}; // namespace osquery

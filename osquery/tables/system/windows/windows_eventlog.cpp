/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Windows.h>
#include <winevt.h>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/events/windows/windowseventlogparser.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/tables/system/windows/windows_eventlog.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kEventLogXmlPrefix = "<QueryList><Query Id=\"0\">";
const std::string kEventLogXmlSuffix = "</Query></QueryList>";

Status parseWelXml(QueryContext& context, std::wstring& xml_event, Row& row) {
  pt::ptree propTree;
  WELEvent windows_event;
  auto xml_status = parseWindowsEventLogXML(propTree, xml_event);
  if (!xml_status.ok()) {
    VLOG(1) << "Error parsing event log XML: " << xml_status.toString();
    return xml_status;
  }

  auto pt_status = parseWindowsEventLogPTree(windows_event, propTree);
  if (!pt_status.ok()) {
    VLOG(1) << "Error parsing event log PTree: " << pt_status.toString();
    return pt_status;
  }

  row["time"] = INTEGER(windows_event.osquery_time);
  row["datetime"] = SQL_TEXT(windows_event.datetime);
  row["channel"] = SQL_TEXT(windows_event.source);
  row["provider_name"] = SQL_TEXT(windows_event.provider_name);
  row["provider_guid"] = SQL_TEXT(windows_event.provider_guid);
  row["computer_name"] = SQL_TEXT(windows_event.computer_name);
  row["eventid"] = INTEGER(windows_event.event_id);
  row["task"] = INTEGER(windows_event.task_id);
  row["level"] = INTEGER(windows_event.level);
  row["pid"] = INTEGER(windows_event.pid);
  row["tid"] = INTEGER(windows_event.tid);

  row["keywords"] = SQL_TEXT(windows_event.keywords);
  row["data"] = SQL_TEXT(windows_event.data);

  if (context.hasConstraint("time_range", EQUALS)) {
    auto time_range = context.constraints["time_range"].getAll(EQUALS);
    row["time_range"] = SQL_TEXT(*time_range.begin());
  } else {
    row["time_range"] = SQL_TEXT("");
  }

  if (context.hasConstraint("timestamp", EQUALS)) {
    auto timestamp = context.constraints["timestamp"].getAll(EQUALS);
    row["timestamp"] = SQL_TEXT(*timestamp.begin());
  }

  if (context.hasConstraint("xpath", EQUALS)) {
    auto xpaths = context.constraints["xpath"].getAll(EQUALS);
    row["xpath"] = SQL_TEXT(*xpaths.begin());
  }

  return Status::success();
}

void renderQueryResults(QueryContext& context,
                        EVT_HANDLE queryResults,
                        RowYield& yield) {
  uint32_t numEventsBlock = 1024;
  uint32_t position = 0;
  std::vector<EVT_HANDLE> events(numEventsBlock);

  // The batch size should be more than 32. It is not documented
  // but `EvtNext` should not fail (RPC_S_INVALID_BOUND error)
  // with low batch size.
  while (numEventsBlock > 32) {
    unsigned long numEvents = 0;
    // Retrieve the events one block at a time
    auto ret = EvtNext(
        queryResults, numEventsBlock, events.data(), INFINITE, 0, &numEvents);
    while (ret != FALSE) {
      for (unsigned long i = 0; i < numEvents; i++) {
        unsigned long renderedBuffSize = 0;
        unsigned long renderedBuffUsed = 0;
        unsigned long propCount = 0;
        position += 1;
        if (!EvtRender(nullptr,
                       events[i],
                       EvtRenderEventXml,
                       renderedBuffSize,
                       nullptr,
                       &renderedBuffUsed,
                       &propCount)) {
          if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            LOG(WARNING) << "Failed to get the size of rendered event "
                         << GetLastError();
            EvtClose(events[i]);
            continue;
          }
        }

        std::vector<wchar_t> renderedContent(renderedBuffUsed);
        renderedBuffSize = renderedBuffUsed;
        if (!EvtRender(nullptr,
                       events[i],
                       EvtRenderEventXml,
                       renderedBuffSize,
                       renderedContent.data(),
                       &renderedBuffUsed,
                       &propCount)) {
          LOG(WARNING) << "Failed to render windows event with "
                       << GetLastError();
          EvtClose(events[i]);
          continue;
        }

        EvtClose(events[i]);

        Row row;
        std::wstringstream xml_event;
        xml_event << renderedContent.data();
        auto status = parseWelXml(context, xml_event.str(), row);
        if (status.ok()) {
          yield(TableRowHolder(new DynamicTableRow(std::move(row))));
        }
      }

      ret = EvtNext(
          queryResults, numEventsBlock, events.data(), INFINITE, 0, &numEvents);
    }

    // While reading a batch of large event log reports `EvtNext` may
    // fail with error code 1734 (RPC_S_INVALID_BOUND) and loose the
    // chunk of events. This is an unusual behavior and not documented.
    // The fix reduces the batch size to half and retries `EvtNext`
    if (RPC_S_INVALID_BOUND == GetLastError()) {
      numEventsBlock = numEventsBlock / 2;

      // Resize the events vector to the current batch size
      events.resize(numEventsBlock);

      // `EvtNext` may update the event position in query handler on
      // failure with RPC_S_INVALID_BOUND error. `EvtSeek` reset the
      // position before calling EvtNext with lower batch size.
      if (!EvtSeek(
              queryResults, position, nullptr, 0, EvtSeekRelativeToFirst)) {
        VLOG(1) << "EvtSeek failed with error " << GetLastError();
      }
      continue;
    }
    break;
  }

  if (ERROR_NO_MORE_ITEMS != GetLastError()) {
    // No need to close the handler after error; The query
    // EvtClose will also close all the event handler
    VLOG(1) << "EvtNext failed with error " << GetLastError();
  }
}

void genXfilterFromConstraints(QueryContext& context, std::string& xfilter) {
  std::vector<std::string> xfilterList;

  auto eids = context.constraints["eventid"].getAll(EQUALS);
  if (!eids.empty()) {
    xfilterList.emplace_back(
        "(EventID=" + osquery::join(eids, ") or (EventID=") + ")");
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
    auto datetime = *times.begin();
    auto time_vec = osquery::split(datetime, ";");

    if (time_vec.size() == 1) {
      auto _start = time_vec.front();
      xfilterList.emplace_back("TimeCreated[@SystemTime&gt;='" + _start + "']");
    } else if (time_vec.size() == 2) {
      auto _start = time_vec.front();
      auto _end = time_vec.at(1);
      xfilterList.emplace_back("TimeCreated[@SystemTime&gt;='" + _start +
                               "' and @SystemTime&lt;='" + _end + "']");
    }
  } else if (!timestamps.empty()) {
    auto time_diff = *timestamps.begin();
    xfilterList.emplace_back(
        "TimeCreated[timediff(@SystemTime) &lt;= " + time_diff + "]");
  }

  xfilter = xfilterList.empty()
                ? "*"
                : "*[System[" + osquery::join(xfilterList, " and ") + "]]";
}

bool shouldHandleXpath(QueryContext& context) {
  // xpaths are mutually execlusive and can't be used with itself
  // and the other constraints
  auto xpaths = context.constraints["xpath"].getAll(EQUALS);
  if (xpaths.size() > 1) {
    return false;
  }

  return !(context.hasConstraint("channel", EQUALS) ||
           context.hasConstraint("time_range", EQUALS) ||
           context.hasConstraint("timestamp", EQUALS));
}

void genWindowsEventLog(RowYield& yield, QueryContext& context) {
  std::set<std::pair<std::string, std::string>> xpath_set;
  auto hasXpath = context.hasConstraint("xpath", EQUALS);

  if (hasXpath && !shouldHandleXpath(context)) {
    LOG(WARNING) << "Xpaths are mutually exclusive and cannot be "
                    "used with constraints (channel, time_range, timestamp)";
    return;
  }

  // Check if the `xpath` constraint is available and query
  // the events with xpath
  if (hasXpath) {
    auto xpaths = context.constraints["xpath"].getAll(EQUALS);
    auto xpath = *xpaths.begin();
    try {
      pt::ptree propTree;
      std::stringstream ss;
      ss << xpath;
      pt::read_xml(ss, propTree);
      auto channel = propTree.get("QueryList.Query.Select.<xmlattr>.Path", "");
      if (!channel.empty()) {
        xpath_set.insert(std::make_pair(channel, xpath));
      } else {
        LOG(WARNING) << "Invalid xpath format: " << xpath;
      }
    } catch (std::exception& e) {
      LOG(WARNING) << "Failed to parse the xpath xml string " << e.what();
      return;
    }

  } else if (context.hasConstraint("channel", EQUALS)) {
    auto channels = context.constraints["channel"].getAll(EQUALS);
    std::string xfilter("");
    genXfilterFromConstraints(context, xfilter);
    std::string welSearchQuery = kEventLogXmlPrefix;

    for (const auto& channel : channels) {
      welSearchQuery += "<Select Path=\"" + channel + "\">";
      welSearchQuery += xfilter;
      welSearchQuery += "</Select>" + kEventLogXmlSuffix;
      xpath_set.insert(std::make_pair(channel, welSearchQuery));
    }

  } else {
    LOG(WARNING) << "Query constraints are invalid: the event "
                    "channel or xpath must be specified";
    return;
  }

  for (const auto& path : xpath_set) {
    auto queryResults =
        EvtQuery(nullptr,
                 stringToWstring(path.first).c_str(),
                 stringToWstring(path.second).c_str(),
                 EvtQueryChannelPath | EvtQueryReverseDirection);

    if (queryResults == nullptr) {
      LOG(WARNING) << "Failed to search event log for query with "
                   << GetLastError();
      return;
    }

    renderQueryResults(context, queryResults, yield);
    EvtClose(queryResults);
  }
}

}; // namespace tables
}; // namespace osquery

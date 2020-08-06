/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <ctime>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/flags.h>
#include <osquery/utils/status/status.h>

namespace osquery {

struct WELEvent final {
  std::time_t osquery_time{0U};
  std::string datetime;

  std::string source;
  std::string provider_name;
  std::string provider_guid;

  std::int64_t event_id{0U};
  std::int64_t task_id{0U};
  std::int64_t level{0U};

  std::string keywords;
  std::string data;
};

// Process event log and generate the property_tree object
Status parseWindowsEventLogXML(boost::property_tree::ptree& event_object,
                               const std::wstring& xml_event);

// Utility function to parse the windows event property tree
Status parseWindowsEventLogPTree(
    WELEvent& windows_event, const boost::property_tree::ptree& event_object);

} // namespace osquery

// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/results.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <set>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <glog/logging.h>

namespace pt = boost::property_tree;
using osquery::Status;

namespace osquery {

/////////////////////////////////////////////////////////////////////////////
// Row - the representation of a row in a set of database results. Row is a
// simple map where individual column names are keys, which map to the Row's
// respective value
/////////////////////////////////////////////////////////////////////////////

Status serializeRow(const Row& r, pt::ptree& tree) {
  try {
    for (auto& i : r) {
      tree.put<std::string>(i.first, i.second);
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeRowJSON(const Row& r, std::string& json) {
  pt::ptree tree;
  try {
    auto status = serializeRow(r, tree);
    if (!status.ok()) {
      return status;
    }
    std::ostringstream ss;
    pt::write_json(ss, tree, false);
    json = ss.str();
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status deserializeRow(const pt::ptree& tree, Row& r) {
  try {
    for (auto& i : tree) {
      if (i.first.length() > 0) {
        r[i.first] = i.second.data();
      }
    }
    return Status(0, "OK");
  } catch (const std::exception& e) {
    LOG(ERROR) << e.what();
    return Status(1, e.what());
  }
}

Status deserializeRowJSON(const std::string& json, Row& r) {
  pt::ptree tree;
  try {
    std::stringstream j;
    j << json;
    pt::read_json(j, tree);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return deserializeRow(tree, r);
}

/////////////////////////////////////////////////////////////////////////////
// QueryData - the representation of a database query result set. It's a
// vector of rows
/////////////////////////////////////////////////////////////////////////////

Status serializeQueryData(const QueryData& q, pt::ptree& tree) {
  try {
    for (const auto& r : q) {
      pt::ptree serialized;
      auto s = serializeRow(r, serialized);
      if (!s.ok()) {
        return s;
      }
      tree.push_back(std::make_pair("", serialized));
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

/////////////////////////////////////////////////////////////////////////////
// DiffResults - the representation of two diffed QueryData result sets.
// Given and old and new QueryData, DiffResults indicates the "added" subset
// of rows and the "removed" subset of Rows
/////////////////////////////////////////////////////////////////////////////

Status serializeDiffResults(const DiffResults& d, pt::ptree& tree) {
  try {
    pt::ptree added;
    auto added_status = serializeQueryData(d.added, added);
    if (!added_status.ok()) {
      return added_status;
    }
    tree.add_child("added", added);

    pt::ptree removed;
    auto removed_status = serializeQueryData(d.removed, removed);
    if (!removed_status.ok()) {
      return removed_status;
    }
    tree.add_child("removed", removed);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeDiffResultsJSON(const DiffResults& d, std::string& json) {
  try {
    pt::ptree tree;
    auto s = serializeDiffResults(d, tree);
    if (!s.ok()) {
      return s;
    }
    std::ostringstream ss;
    pt::write_json(ss, tree, false);
    json = ss.str();
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

DiffResults diff(const QueryData& old_, const QueryData& new_) {
  DiffResults r;
  QueryData overlap;

  for (const auto& i : new_) {
    auto item = std::find(old_.begin(), old_.end(), i);
    if (item != old_.end()) {
      overlap.push_back(i);
    } else {
      r.added.push_back(i);
    }
  }

  std::multiset<Row> overlap_set(overlap.begin(), overlap.end());

  std::multiset<Row> old_set(old_.begin(), old_.end());

  std::set_difference(old_set.begin(),
                      old_set.end(),
                      overlap_set.begin(),
                      overlap_set.end(),
                      std::back_inserter(r.removed));

  return r;
}

/////////////////////////////////////////////////////////////////////////////
// HistoricalQueryResults - the representation of the historical results of
// a particlar scheduled database query.
/////////////////////////////////////////////////////////////////////////////

Status serializeHistoricalQueryResultsJSON(const HistoricalQueryResults& r,
                                           std::string& json) {
  try {
    pt::ptree tree;
    auto s = serializeHistoricalQueryResults(r, tree);
    if (!s.ok()) {
      return s;
    }
    std::ostringstream ss;
    pt::write_json(ss, tree, false);
    json = ss.str();
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeHistoricalQueryResults(const HistoricalQueryResults& r,
                                       pt::ptree& tree) {
  try {
    pt::ptree mostRecentResults;

    pt::ptree most_recent_serialized;
    auto mrr_status =
        serializeQueryData(r.mostRecentResults.second, most_recent_serialized);
    if (!mrr_status.ok()) {
      return mrr_status;
    }
    mostRecentResults.add_child(
        boost::lexical_cast<std::string>(r.mostRecentResults.first),
        most_recent_serialized);
    tree.add_child("mostRecentResults", mostRecentResults);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status deserializeHistoricalQueryResults(const pt::ptree& tree,
                                         HistoricalQueryResults& r) {
  try {
    for (const auto& v : tree.get_child("mostRecentResults")) {
      try {
        int execution = boost::lexical_cast<int>(v.first);
        r.mostRecentResults.first = execution;
      } catch (const boost::bad_lexical_cast& e) {
        return Status(1, e.what());
      }

      QueryData q;
      for (const auto& each : v.second) {
        Row row_;
        for (const auto& item : each.second) {
          row_[item.first] = item.second.get_value<std::string>();
        }
        q.push_back(row_);
      }
      r.mostRecentResults.second = q;
    }

    return Status(0, "OK");
  } catch (const std::exception& e) {
    LOG(ERROR) << e.what();
    return Status(1, e.what());
  }
}

Status deserializeHistoricalQueryResultsJSON(const std::string& json,
                                             HistoricalQueryResults& r) {
  pt::ptree tree;
  try {
    std::stringstream j;
    j << json;
    pt::read_json(j, tree);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return deserializeHistoricalQueryResults(tree, r);
}

/////////////////////////////////////////////////////////////////////////////
// ScheduledQueryLogItem - the representation of a log result occuring when a
// s schedueld query yields operating system state change.
/////////////////////////////////////////////////////////////////////////////

Status serializeScheduledQueryLogItem(const ScheduledQueryLogItem& i,
                                      boost::property_tree::ptree& tree) {
  try {
    pt::ptree diffResults;
    auto diff_results_status = serializeDiffResults(i.diffResults, diffResults);
    if (!diff_results_status.ok()) {
      return diff_results_status;
    }

    tree.add_child("diffResults", diffResults);
    tree.put<std::string>("name", i.name);
    tree.put<std::string>("hostname", i.hostname);
    tree.put<std::string>("calendarTime", i.calendarTime);
    tree.put<int>("unixTime", i.unixTime);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeEvent(const ScheduledQueryLogItem& item,
                      const boost::property_tree::ptree& event,
                      boost::property_tree::ptree& tree) {
  tree.put<std::string>("name", item.name);
  tree.put<std::string>("hostname", item.hostname);
  tree.put<std::string>("calendarTime", item.calendarTime);
  tree.put<int>("unixTime", item.unixTime);

  pt::ptree columns;
  for (auto& i : event) {
    columns.put<std::string>(i.first, i.second.get_value<std::string>());
  }

  tree.add_child("columns", columns);
  return Status(0, "OK");
}

Status serializeScheduledQueryLogItemAsEvents(
    const ScheduledQueryLogItem& item, boost::property_tree::ptree& tree) {
  try {
    pt::ptree diff_results;
    auto status = serializeDiffResults(item.diffResults, diff_results);
    if (!status.ok()) {
      return status;
    }

    for (auto& i : diff_results) {
      for (auto& j : i.second) {
        pt::ptree event;
        serializeEvent(item, j.second, event);
        event.put<std::string>("action", i.first);
        tree.push_back(std::make_pair("", event));
      }
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

Status serializeScheduledQueryLogItemAsEventsJSON(
    const ScheduledQueryLogItem& i, std::string& json) {
  try {
    pt::ptree tree;
    auto s = serializeScheduledQueryLogItemAsEvents(i, tree);
    if (!s.ok()) {
      return s;
    }
    std::ostringstream ss;
    for (auto& event : tree) {
      pt::write_json(ss, event.second, false);
    }
    json = ss.str();
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeScheduledQueryLogItemJSON(const ScheduledQueryLogItem& i,
                                          std::string& json) {
  try {
    pt::ptree tree;
    auto s = serializeScheduledQueryLogItem(i, tree);
    if (!s.ok()) {
      return s;
    }
    std::ostringstream ss;
    pt::write_json(ss, tree, false);
    json = ss.str();
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}
}

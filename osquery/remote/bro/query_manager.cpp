/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>
#include <list>
#include <sstream>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/remote/bro/query_manager.h"

namespace osquery {

Status QueryManager::reset() {
  std::vector<std::string> queryIDs = getQueryIDs();

  // Collect query strings
  std::vector<std::string> queries;
  for (const auto& id : scheduleQueries_) {
    queries.push_back(std::get<1>(id.second));
  }
  for (const auto& id : oneTimeQueries_) {
    queries.push_back(std::get<1>(id.second));
  }

  for (const auto& queryID : queryIDs) {
    std::string query;
    std::string qType;
    findQueryAndType(queryID, qType, query);
    removeQueryEntry(query);
  }

  return Status(0, "OK");
}

std::string QueryManager::addOneTimeQueryEntry(const SubscriptionRequest& qr) {
  const auto queryID = std::to_string(nextUID_++);
  auto status = addQueryEntry(queryID, qr, "ONETIME");
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return "";
  }
  return queryID;
}

Status QueryManager::addScheduleQueryEntry(const SubscriptionRequest& qr) {
  const auto queryID = std::to_string(this->nextUID_++);
  return addQueryEntry(queryID, qr, "SCHEDULE");
}

Status QueryManager::addQueryEntry(const std::string& queryID,
                                   const SubscriptionRequest& qr,
                                   const std::string& qtype) {
  const auto& query = qr.query;
  const auto& cookie = qr.cookie;
  const auto& response_event = qr.response_event;
  const auto& response_topic = qr.response_topic;
  const int& interval = qr.interval;
  const bool& added = qr.added;
  const bool& removed = qr.removed;
  const bool& snapshot = qr.snapshot;
  if (scheduleQueries_.count(queryID) > 0 or
      oneTimeQueries_.count(queryID) > 0) {
    return Status(1, "QueryID '" + queryID + "' already exists");
  }

  if (qtype == "SCHEDULE") {
    scheduleQueries_[queryID] =
        ScheduleQueryEntry{queryID, query, interval, added, removed, snapshot};
  } else if (qtype == "ONETIME") {
    oneTimeQueries_[queryID] = OneTimeQueryEntry{queryID, query};
  } else {
    return Status(1, "Unknown query type '" + qtype + "'");
  }

  eventCookies_[queryID] = cookie;
  eventNames_[queryID] = response_event;
  eventTopics_[queryID] = response_topic;
  return Status(0, "OK");
}

std::string QueryManager::findIDForQuery(const std::string& query) {
  // Search the queryID for this specific query
  for (const auto& e : scheduleQueries_) {
    const auto& queryID = e.first;
    const ScheduleQueryEntry& bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }

  for (const auto& e : oneTimeQueries_) {
    const auto& queryID = e.first;
    const OneTimeQueryEntry& bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }
  return "";
}

Status QueryManager::findQueryAndType(const std::string& queryID,
                                      std::string& qtype,
                                      std::string& query) {
  if (scheduleQueries_.count(queryID) > 0) {
    qtype = "SCHEDULE";
    query = std::get<1>(scheduleQueries_.at(queryID));
  } else if (oneTimeQueries_.count(queryID) > 0) {
    qtype = "ONETIME";
    query = std::get<1>(oneTimeQueries_.at(queryID));
  } else {
    return Status(1, "QueryID '" + queryID + "' not in brokerQueries");
  }
  return Status(0, "OK");
}

Status QueryManager::removeQueryEntry(const std::string& query) {
  const auto& queryID = findIDForQuery(query);
  if (queryID == "") {
    return Status(1, "Unable to find ID for query '" + query + "'");
  }

  // Delete query info
  eventCookies_.erase(queryID);
  eventTopics_.erase(queryID);
  eventNames_.erase(queryID);
  if (scheduleQueries_.count(queryID) >= 1) {
    VLOG(1) << "Deleting schedule query '" << query << "' with queryID '"
            << queryID << "'";
    scheduleQueries_.erase(queryID);
  }
  if (oneTimeQueries_.count(queryID) >= 1) {
    VLOG(1) << "Deleting onetime query '" << query << "' with queryID '"
            << queryID << "'";
    oneTimeQueries_.erase(queryID);
  }

  return Status(0, "OK");
}

std::string QueryManager::getQueryConfigString() {
  // Format each query
  std::vector<std::string> scheduleQ;
  for (const auto& bq : scheduleQueries_) {
    auto i = bq.second;
    std::stringstream ss;
    ss << "\"" << std::get<0>(i) << "\": {\"query\": \"" << std::get<1>(i)
       << ";\", \"interval\": " << std::get<2>(i)
       << ", \"added\": " << std::get<3>(i)
       << ", \"removed\": " << std::get<4>(i)
       << ", \"snapshot\": " << std::get<5>(i) << "}";
    std::string q = ss.str();
    scheduleQ.push_back(q);
  }

  // Assemble queries
  std::stringstream ss;
  for (size_t i = 0; i < scheduleQ.size(); ++i) {
    if (i != 0)
      ss << ",";
    ss << scheduleQ[i];
  }
  const auto& queries = ss.str();
  std::string config =
      std::string("{\"schedule\": {") + queries + std::string("} }");

  return config;
}

Status QueryManager::updateSchedule() {
  std::map<std::string, std::string> new_config_schedule;

  VLOG(1) << "Applying new schedule based on bro queries";
  for (auto const& c : initial_config) {
    // Base config
    auto doc_base = JSON::newObject();
    auto clone_base = c.second;
    stripConfigComments(clone_base);

    if (!doc_base.fromString(clone_base) || !doc_base.doc().IsObject()) {
      LOG(WARNING) << "Error parsing the base config JSON";
    }

    // Bro config
    auto doc_bro = JSON::newObject();
    auto clone_bro = getQueryConfigString();
    stripConfigComments(clone_bro);

    if (!doc_bro.fromString(clone_bro) || !doc_bro.doc().IsObject()) {
      LOG(WARNING) << "Error parsing the bro config JSON";
    }

    // Remove old base schedule
    if (doc_base.doc().HasMember("schedule")) {
      doc_base.doc().RemoveMember("schedule");
    }

    // Add new bro schedule
    if (!doc_bro.doc().HasMember("schedule")) {
      LOG(WARNING) << "Bro config has no member schedule";
    }
    doc_base.add("schedule", doc_bro.doc()["schedule"]);

    std::string result_json;
    doc_base.toString(result_json);

    new_config_schedule[c.first] = result_json;
  }
  Config::get().update(new_config_schedule);

  return Status(0, "OK");
}

std::string QueryManager::getEventCookie(const std::string& queryID) {
  return eventCookies_.at(queryID);
}

std::string QueryManager::getEventName(const std::string& queryID) {
  return eventNames_.at(queryID);
}

std::string QueryManager::getEventTopic(const std::string& queryID) {
  return eventTopics_.at(queryID);
}

std::vector<std::string> QueryManager::getQueryIDs() {
  // Collect queryIDs
  std::vector<std::string> queryIDs;
  for (const auto& id : scheduleQueries_) {
    queryIDs.push_back(id.first);
  }
  for (const auto& id : oneTimeQueries_) {
    queryIDs.push_back(id.first);
  }

  return queryIDs;
}
} // namespace osquery

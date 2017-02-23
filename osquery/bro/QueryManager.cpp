/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>
#include <list>
#include <sstream>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/bro/QueryManager.h"

namespace osquery {

QueryManager* QueryManager::kInstance_ = nullptr;

QueryManager::QueryManager() {}

std::string QueryManager::addOneTimeQueryEntry(const SubscriptionRequest& qr) {
  const auto queryID = std::to_string(_nextUID++);
  auto status = addQueryEntry(queryID, qr, "ONETIME");
  if (status.ok())
    return queryID;
  else
    LOG(WARNING) << status.getMessage();
  return "-1";
}

Status QueryManager::addScheduleQueryEntry(const SubscriptionRequest& qr) {
  const auto queryID = std::to_string(this->_nextUID++);
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
  if (scheduleQueries.count(queryID) > 0 or oneTimeQueries.count(queryID) > 0) {
    return Status(1, "QueryID '" + queryID + "' already exists");
  }

  if (qtype == "SCHEDULE")
    scheduleQueries[queryID] =
        ScheduleQueryEntry{queryID, query, interval, added, removed, snapshot};
  else if (qtype == "ONETIME")
    oneTimeQueries[queryID] = OneTimeQueryEntry{queryID, query};
  else
    return Status(1, "Unknown query type :" + qtype);
  eventCookies[queryID] = cookie;
  eventNames[queryID] = response_event;
  eventTopics[queryID] = response_topic;
  return Status(0, "OK");
}

std::string QueryManager::findIDForQuery(const std::string& query) {
  // Search the queryID for this specific query
  for (const auto& e : scheduleQueries) {
    const auto& queryID = e.first;
    const ScheduleQueryEntry& bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }

  for (const auto& e : oneTimeQueries) {
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
  if (scheduleQueries.count(queryID) > 0) {
    qtype = "SCHEDULE";
    query = std::get<1>(scheduleQueries.at(queryID));
  } else if (oneTimeQueries.count(queryID) > 0) {
    qtype = "ONETIME";
    query = std::get<1>(oneTimeQueries.at(queryID));
  } else {
    return Status(1, "QueryID " + queryID + " not in brokerQueries");
  }
  return Status(0, "OK");
}

Status QueryManager::removeQueryEntry(const std::string& query) {
  const auto& queryID = findIDForQuery(query);
  if (queryID == "") {
    return Status(1, "Unable to find ID for query: " + query);
  }

  // Delete query info
  eventCookies.erase(queryID);
  eventTopics.erase(queryID);
  eventNames.erase(queryID);
  if (scheduleQueries.count(queryID) >= 1) {
    LOG(INFO) << "Deleting schedule query '" << query << "' with queryID '"
              << queryID << "'";
    scheduleQueries.erase(queryID);
  }
  if (oneTimeQueries.count(queryID) >= 1) {
    LOG(INFO) << "Deleting onetime query '" << query << "' with queryID '"
              << queryID << "'";
    oneTimeQueries.erase(queryID);
  }

  return Status(0, "OK");
}

std::string QueryManager::getQueryConfigString() {
  // Format each query
  std::vector<std::string> scheduleQ;
  for (const auto& bq : scheduleQueries) {
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

std::string QueryManager::getEventCookie(const std::string& queryID) {
  return eventCookies.at(queryID);
}

std::string QueryManager::getEventName(const std::string& queryID) {
  return eventNames.at(queryID);
}

std::string QueryManager::getEventTopic(const std::string& queryID) {
  return eventTopics.at(queryID);
}
}

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/status.h>
#include <osquery/system.h>

#include "osquery/bro/QueryManager.h"

#include <iostream>
#include <list>
#include <sstream>
#include <stdlib.h> /* srand, rand */
#include <time.h>

namespace osquery {

QueryManager* QueryManager::_instance = nullptr;

QueryManager::QueryManager() {}

std::string QueryManager::addOneTimeQueryEntry(const SubscriptionRequest& qr) {
  const std::string queryID = std::to_string(this->_nextUID++);
  if (addQueryEntry(queryID, qr, "ONETIME").ok())
    return queryID;
  else
    return "-1";
}

osquery::Status QueryManager::addScheduleQueryEntry(
    const SubscriptionRequest& qr) {
  const std::string queryID = std::to_string(this->_nextUID++);
  return addQueryEntry(queryID, qr, "SCHEDULE");
}

Status QueryManager::addQueryEntry(const std::string& queryID,
                                   const SubscriptionRequest& qr,
                                   const std::string& qtype) {
  std::string query = qr.query;
  std::string cookie = qr.cookie;
  std::string response_event = qr.response_event;
  std::string response_topic = qr.response_topic;
  int interval = qr.interval;
  bool added = qr.added;
  bool removed = qr.removed;
  bool snapshot = qr.snapshot;
  if (this->scheduleQueries.find(queryID) != this->scheduleQueries.end() or
      this->oneTimeQueries.find(queryID) != this->oneTimeQueries.end()) {
    LOG(ERROR) << "QueryID '" << queryID << "' already exists";
    return Status(1, "Duplicate queryID");
  }

  if (qtype == "SCHEDULE")
    this->scheduleQueries[queryID] =
        ScheduleQueryEntry{queryID, query, interval, added, removed, snapshot};
  else if (qtype == "ONETIME")
    this->oneTimeQueries[queryID] = OneTimeQueryEntry{queryID, query};
  else
    LOG(ERROR) << "Unknown query type :" << qtype;
  this->eventCookies[queryID] = cookie;
  this->eventNames[queryID] = response_event;
  this->eventTopics[queryID] = response_topic;
  return Status(0, "OK");
}

std::string QueryManager::findIDForQuery(const std::string& query) {
  // Search the queryID for this specific query
  for (const auto& e : this->scheduleQueries) {
    std::string queryID = e.first;
    ScheduleQueryEntry bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }

  for (const auto& e : this->oneTimeQueries) {
    std::string queryID = e.first;
    OneTimeQueryEntry bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }
  return "";
}

Status QueryManager::findQueryAndType(const std::string& queryID,
                                      std::string& qtype,
                                      std::string& query) {
  if (this->scheduleQueries.find(queryID) != this->scheduleQueries.end()) {
    qtype = "SCHEDULE";
    query = std::get<1>(this->scheduleQueries.at(queryID));
  } else if (this->oneTimeQueries.find(queryID) != this->oneTimeQueries.end()) {
    qtype = "ONETIME";
    query = std::get<1>(this->oneTimeQueries.at(queryID));
  } else {
    LOG(ERROR) << "QueryID not in brokerQueries";
    return Status(1, "Unknown QueryID");
  }
  return Status(0, "OK");
}

Status QueryManager::removeQueryEntry(const std::string& query) {
  std::string queryID = this->findIDForQuery(query);
  if (queryID == "") {
    LOG(ERROR) << "Unable to find ID for query: '" << query << "'";
    return Status(1, "Unable to find ID for query");
  }

  // Delete query info
  this->eventCookies.erase(queryID);
  this->eventTopics.erase(queryID);
  this->eventNames.erase(queryID);
  if (this->scheduleQueries.count(queryID) >= 1) {
    LOG(INFO) << "Deleting schedule query '" << query << "' with queryID '"
              << queryID << "'";
    this->scheduleQueries.erase(queryID);
  }
  if (this->oneTimeQueries.count(queryID) >= 1) {
    LOG(INFO) << "Deleting onetime query '" << query << "' with queryID '"
              << queryID << "'";
    this->oneTimeQueries.erase(queryID);
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
  std::string queries = ss.str();
  std::string config =
      std::string("{\"schedule\": {") + queries + std::string("} }");

  return config;
}

std::string QueryManager::getEventCookie(const std::string& queryID) {
  return this->eventCookies.at(queryID);
}

std::string QueryManager::getEventName(const std::string& queryID) {
  return this->eventNames.at(queryID);
}

std::string QueryManager::getEventTopic(const std::string& queryID) {
  return this->eventTopics.at(queryID);
}
}

/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <iostream>
#include <list>
#include <map>

#include <osquery/status.h>
#include <osquery/system.h>

namespace osquery {

// ID, query, interval, added, removed, snapshot
typedef std::tuple<std::string, std::string, int, bool, bool, bool>
    ScheduleQueryEntry;
typedef std::tuple<std::string, std::string> OneTimeQueryEntry;

struct SubscriptionRequest {
  std::string query; // The requested SQL query
  std::string response_event; // The event name for the response event
  std::string response_topic; // The topic name for the response event
  std::string cookie = "";
  uint64_t interval = 10;
  bool added = true;
  bool removed = false;
  bool snapshot = false;
};

class QueryManager : private boost::noncopyable {
 private:
  QueryManager() {}

 public:
  /// Get a singleton instance of the QueryManager class
  static QueryManager& getInstance() {
    static QueryManager qm;
    return qm;
  };

  std::string addOneTimeQueryEntry(const SubscriptionRequest& qr);

  Status addScheduleQueryEntry(const SubscriptionRequest& qr);

  Status addQueryEntry(const std::string& queryID,
                       const SubscriptionRequest& qr,
                       const std::string& qtype);

  std::string findIDForQuery(const std::string& query);

  Status findQueryAndType(const std::string& queryID,
                          std::string& qtype,
                          std::string& query);

  Status removeQueryEntry(const std::string& query);

  std::string getQueryConfigString();

  std::string getEventCookie(const std::string& queryID);

  std::string getEventName(const std::string& queryID);

  std::string getEventTopic(const std::string& queryID);

 private:
  // Next unique QueryID
  int nextUID_ = 1;

  // Collection of SQL Subscription queries, Key: QueryID
  std::map<std::string, ScheduleQueryEntry> scheduleQueries_;
  // Collection of SQL One-Time Subscription queries, Key: QueryID
  std::map<std::string, OneTimeQueryEntry> oneTimeQueries_;

  // Some mapping to maintain the SQL subscriptions
  //  Key: QueryID, Value: Event Cookie to use for the response
  std::map<std::string, std::string> eventCookies_;
  //  Key: QueryID, Value: Event Name to use for the response
  std::map<std::string, std::string> eventNames_;
  //  Key: QueryID, Value: Topic to use for the response
  std::map<std::string, std::string> eventTopics_;
};
}

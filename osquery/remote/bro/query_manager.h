/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <iostream>
#include <list>
#include <map>

#include <osquery/status.h>
#include <osquery/system.h>

namespace osquery {

/**
 * @brief Internal definition of a query for scheduling
 *
 * The fields correspond to ID, query, interval, added, removed, snapshot. This
 * representation is used to keep track of active schedule subscriptions.
 */
typedef std::tuple<std::string, std::string, int, bool, bool, bool>
    ScheduleQueryEntry;
/**
 * @brief Internal definition of a query for one-time execution
 *
 * The fields correspond to ID, query. This representation is used to keep track
 * of active one-time query executions.
 */
typedef std::tuple<std::string, std::string> OneTimeQueryEntry;

/**
 * @brief Internal definition of a subscription request
 *
 * A subscription request is a common data structure to describe the incoming
 * query request and to hold its parameters. This definition is valid for all
 * request types in BrokerRequestType.
 */
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

/**
 * @brief Manager class for queries that are received via broker.
 *
 * The QueryManager is a singleton to keep track of queries that are requested
 * via broker.
 */
class QueryManager : private boost::noncopyable {
 private:
  /**
   * @brief The private constructor of the class.
   *
   * Nothing to do here.
   */
  QueryManager() {}

 public:
  /// Get a singleton instance of the QueryManager class
  static QueryManager& get() {
    static QueryManager qm;
    return qm;
  };

  /**
   * @brief Reset the QueryManager to its initial state.
   *
   * This makes the BrokerManager to remove all schedule and one-time queries
   * from tracking
   */
  Status reset();

  /**
   * @brief Add a one-time query to tracking
   *
   * @param qr the subscription request for this one-time query
   * @return the unique queryID assigned this query
   */
  std::string addOneTimeQueryEntry(const SubscriptionRequest& qr);

  /**
   * @brief Add a schedule query to tracking
   *
   * @param qr the subscription request for this schedule query
   * @return
   */
  Status addScheduleQueryEntry(const SubscriptionRequest& qr);

  /**
   * @brief Add a query to tracking with fixed properties
   *
   * @param queryID the queryID to use for this query
   * @param qr the subscription request for this query
   * @param qtype the type of the query ("SCHEDULE" or "ONETIME")
   * @return
   */
  Status addQueryEntry(const std::string& queryID,
                       const SubscriptionRequest& qr,
                       const std::string& qtype);

  /// Find the queryID for a query that is tracked given by the query string
  std::string findIDForQuery(const std::string& query);

  /// Find the query string and the query type for a query that is tracked given
  /// by the queryID
  Status findQueryAndType(const std::string& queryID,
                          std::string& qtype,
                          std::string& query);

  /// Remove a query from tracking given by the query string
  Status removeQueryEntry(const std::string& query);

  /// Generate configuration data for the query schedule (osqueryd) from the
  /// broker query tracking
  std::string getQueryConfigString();

  /// Get the cookie the was given in the subscription request of a query given
  /// by the queryID
  std::string getEventCookie(const std::string& queryID);

  /// Get the response event name the was given in the subscription request of a
  /// query given by the queryID
  std::string getEventName(const std::string& queryID);

  /// Get the response event topic the was given in the subscription request of
  /// a query given by the queryID
  std::string getEventTopic(const std::string& queryID);

  /// Get a vector of all currently tracked queryIDs
  std::vector<std::string> getQueryIDs();

 private:
  // Next unique QueryID
  int nextUID_ = 1;

  // Collection of SQL Schedule Subscription queries, Key: QueryID
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

 private:
  friend class QueryManagerTests;

  FRIEND_TEST(QueryManagerTests, test_reset);
};
} // namespace osquery
